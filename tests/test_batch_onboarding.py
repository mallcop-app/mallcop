"""Tests for batch onboarding: cold start detection, hard constraints, feedback records."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.batch import build_batch_context, is_cold_start, run_batch
from mallcop.actors.runtime import BatchResult, RunResult
from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.schemas import (
    Baseline,
    Finding,
    FindingStatus,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    fid: str = "fnd_001",
    detector: str = "new-actor",
    severity: Severity = Severity.WARN,
) -> Finding:
    return Finding(
        id=fid,
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        detector=detector,
        event_ids=["evt_001"],
        title=f"Finding {fid}",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "alice"},
    )


def _empty_baseline(**overrides: Any) -> Baseline:
    defaults: dict[str, Any] = {
        "frequency_tables": {},
        "known_entities": {},
        "relationships": {},
        "actor_context": {},
    }
    defaults.update(overrides)
    return Baseline(
        frequency_tables=defaults["frequency_tables"],
        known_entities=defaults["known_entities"],
        relationships=defaults["relationships"],
        actor_context=defaults["actor_context"],
    )


def _make_run_result(
    finding_id: str = "fnd_001",
    action: str = "resolved",
    confidence: float = 0.8,
) -> RunResult:
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding_id,
            action=ResolutionAction(action),
            reason="Test reason",
            confidence=confidence,
        ),
        tokens_used=100,
        iterations=1,
        tool_calls=2,
        distinct_tools=1,
    )


# ---------------------------------------------------------------------------
# is_cold_start() tests
# ---------------------------------------------------------------------------

class TestIsColdStart:
    def test_empty_baseline_is_cold_start(self):
        """Empty baseline (no actors, no frequency data) is cold start."""
        baseline = _empty_baseline()
        assert is_cold_start(baseline) is True

    def test_thin_actor_context_is_cold_start(self):
        """Fewer than 3 actors in actor_context → cold start."""
        from mallcop.schemas import ActorProfile
        now = datetime.now(timezone.utc)
        baseline = _empty_baseline(
            actor_context={
                "alice": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[]),
                "bob": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[]),
            },
            frequency_tables={"actor:alice": {"count": 10}, "actor:bob": {"count": 5}},
        )
        assert is_cold_start(baseline) is True

    def test_thin_frequency_data_is_cold_start(self):
        """Fewer than 50 frequency table entries → cold start."""
        from mallcop.schemas import ActorProfile
        now = datetime.now(timezone.utc)
        baseline = _empty_baseline(
            actor_context={
                "alice": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[]),
                "bob": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[]),
                "carol": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[]),
            },
            frequency_tables={f"key_{i}": {} for i in range(30)},
        )
        assert is_cold_start(baseline) is True

    def test_warm_baseline_not_cold_start(self):
        """3+ actors AND 50+ freq entries → not cold start."""
        from mallcop.schemas import ActorProfile
        now = datetime.now(timezone.utc)
        baseline = _empty_baseline(
            actor_context={
                f"actor_{i}": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[])
                for i in range(5)
            },
            frequency_tables={f"key_{i}": {} for i in range(60)},
        )
        assert is_cold_start(baseline) is False

    def test_exactly_3_actors_50_entries_not_cold_start(self):
        """Boundary: exactly 3 actors AND 50 entries → not cold start."""
        from mallcop.schemas import ActorProfile
        now = datetime.now(timezone.utc)
        baseline = _empty_baseline(
            actor_context={
                f"actor_{i}": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[])
                for i in range(3)
            },
            frequency_tables={f"key_{i}": {} for i in range(50)},
        )
        assert is_cold_start(baseline) is False

    def test_none_baseline_is_cold_start(self):
        """None baseline treated as cold start."""
        assert is_cold_start(None) is True


# ---------------------------------------------------------------------------
# Cold start framing in build_batch_context()
# ---------------------------------------------------------------------------

class TestColdStartFraming:
    def test_cold_start_framing_prepended(self):
        """Cold start framing added when baseline is thin."""
        baseline = _empty_baseline()
        findings = [_make_finding("f1"), _make_finding("f2")]
        context = build_batch_context(findings, baseline=baseline)
        assert context is not None
        assert "new deployment" in context.lower() or "learn" in context.lower()

    def test_warm_baseline_no_cold_start_framing(self):
        """No cold start framing when baseline is warm."""
        from mallcop.schemas import ActorProfile
        now = datetime.now(timezone.utc)
        baseline = _empty_baseline(
            actor_context={
                f"actor_{i}": ActorProfile(location=None, timezone=None, type="human", last_confirmed=now, source_feedback_ids=[])
                for i in range(5)
            },
            frequency_tables={f"key_{i}": {} for i in range(60)},
        )
        findings = [_make_finding("f1"), _make_finding("f2")]
        context = build_batch_context(findings, baseline=baseline)
        assert context is not None
        assert "new deployment" not in context.lower()

    def test_no_baseline_produces_normal_context(self):
        """build_batch_context without baseline produces normal framing."""
        findings = [_make_finding("f1"), _make_finding("f2")]
        context = build_batch_context(findings)
        assert context is not None
        assert "You have 2 findings" in context

    def test_single_finding_still_returns_none(self):
        """Single finding: no batch context even with cold start."""
        baseline = _empty_baseline()
        context = build_batch_context([_make_finding()], baseline=baseline)
        assert context is None


# ---------------------------------------------------------------------------
# Hard constraint: NON_BULK_RESOLVABLE detectors
# ---------------------------------------------------------------------------

class TestHardConstraints:
    def test_priv_escalation_is_non_bulk_resolvable(self):
        """priv-escalation findings are flagged as non-bulk-resolvable."""
        from mallcop.actors.batch import is_non_bulk_resolvable
        finding = _make_finding(detector="priv-escalation")
        assert is_non_bulk_resolvable(finding) is True

    def test_new_external_access_is_non_bulk_resolvable(self):
        """new-external-access findings are flagged as non-bulk-resolvable."""
        from mallcop.actors.batch import is_non_bulk_resolvable
        finding = _make_finding(detector="new-external-access")
        assert is_non_bulk_resolvable(finding) is True

    def test_export_action_is_non_bulk_resolvable(self):
        """Findings with export/dump/backup in action are non-bulk-resolvable."""
        from mallcop.actors.batch import is_non_bulk_resolvable
        f = _make_finding()
        f.metadata["action"] = "export-data"
        assert is_non_bulk_resolvable(f) is True

    def test_dump_action_is_non_bulk_resolvable(self):
        """Findings with dump in action are non-bulk-resolvable."""
        from mallcop.actors.batch import is_non_bulk_resolvable
        f = _make_finding()
        f.metadata["action"] = "database-dump"
        assert is_non_bulk_resolvable(f) is True

    def test_routine_detector_is_bulk_resolvable(self):
        """Routine detector (new-actor, unusual-timing) is bulk resolvable."""
        from mallcop.actors.batch import is_non_bulk_resolvable
        assert is_non_bulk_resolvable(_make_finding(detector="new-actor")) is False
        assert is_non_bulk_resolvable(_make_finding(detector="unusual-timing")) is False

    def test_non_bulk_finding_surfaced_individually_in_batch(self):
        """Non-bulk findings get no batch_context kwarg passed to actor_runner."""
        received_kwargs: list[dict] = []

        def capturing_runner(finding: Finding, **kwargs: Any) -> RunResult:
            received_kwargs.append({"finding_id": finding.id, "batch_context": kwargs.get("batch_context")})
            return _make_run_result(finding_id=finding.id)

        bulk_finding = _make_finding("f_bulk", detector="new-actor")
        nonbulk_finding = _make_finding("f_nonbulk", detector="priv-escalation", severity=Severity.CRITICAL)

        run_batch(capturing_runner, [bulk_finding, nonbulk_finding])

        by_id = {r["finding_id"]: r for r in received_kwargs}
        # Non-bulk finding gets no batch context (presented individually)
        assert by_id["f_nonbulk"]["batch_context"] is None
        # Bulk finding gets batch context
        assert by_id["f_bulk"]["batch_context"] is not None


# ---------------------------------------------------------------------------
# Batch resolutions create FeedbackRecords
# ---------------------------------------------------------------------------

class TestBatchFeedbackRecords:
    def test_resolved_findings_create_feedback_records(self):
        """Each resolved finding during batch creates a FeedbackRecord."""
        from datetime import datetime
        findings = [_make_finding("f1"), _make_finding("f2")]

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return _make_run_result(finding_id=finding.id, action="resolved")

        result = run_batch(mock_runner, findings)
        assert hasattr(result, "feedback_records")
        assert len(result.feedback_records) == 2

    def test_feedback_records_have_batch_source(self):
        """Batch feedback records are tagged with source='batch'."""
        findings = [_make_finding("f1")]

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return _make_run_result(finding_id=finding.id, action="resolved")

        result = run_batch(mock_runner, findings)
        assert result.feedback_records[0].source == "batch"

    def test_escalated_findings_do_not_create_feedback_records(self):
        """Only resolved findings generate feedback (escalations are unresolved)."""
        findings = [_make_finding("f1"), _make_finding("f2")]

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            if finding.id == "f1":
                return _make_run_result(finding_id=finding.id, action="resolved")
            return _make_run_result(finding_id=finding.id, action="escalated")

        result = run_batch(mock_runner, findings)
        assert len(result.feedback_records) == 1
        assert result.feedback_records[0].finding_id == "f1"

    def test_feedback_records_have_correct_structure(self):
        """FeedbackRecord from batch has required fields populated."""
        findings = [_make_finding("f1")]

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return _make_run_result(finding_id=finding.id, action="resolved")

        result = run_batch(mock_runner, findings)
        rec = result.feedback_records[0]
        assert rec.finding_id == "f1"
        assert rec.human_action == HumanAction.AGREE
        assert rec.original_action == "resolved"
        assert rec.source == "batch"

    def test_none_resolution_does_not_create_feedback_record(self):
        """RunResult with no resolution (error) doesn't create a feedback record."""
        findings = [_make_finding("f1")]

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=None,
                tokens_used=50,
                iterations=1,
                tool_calls=0,
                distinct_tools=0,
            )

        result = run_batch(mock_runner, findings)
        assert len(result.feedback_records) == 0
