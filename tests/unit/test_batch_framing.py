"""Tests for batch framing context in run_batch()."""

from datetime import datetime, timezone

from mallcop.actors.runtime import build_batch_context, run_batch, RunResult, BatchResult
from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.schemas import Finding, Severity, FindingStatus


def _make_finding(
    id: str, detector: str = "new-actor", severity: Severity = Severity.WARN
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime.now(timezone.utc),
        detector=detector,
        event_ids=["e1"],
        title="Test finding",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


class TestBuildBatchContext:
    def test_multi_finding_batch_has_correct_counts(self):
        """Batch framing message contains correct detector/severity counts."""
        findings = [
            _make_finding("f1", detector="new-actor", severity=Severity.WARN),
            _make_finding("f2", detector="new-actor", severity=Severity.WARN),
            _make_finding("f3", detector="new-actor", severity=Severity.WARN),
            _make_finding("f4", detector="volume-anomaly", severity=Severity.WARN),
            _make_finding("f5", detector="volume-anomaly", severity=Severity.WARN),
            _make_finding("f6", detector="config-drift", severity=Severity.INFO),
            _make_finding("f7", detector="config-drift", severity=Severity.INFO),
        ]

        ctx = build_batch_context(findings)

        assert ctx is not None
        assert "You have 7 findings" in ctx
        assert "2 from config-drift(info)" in ctx
        assert "3 from new-actor(warn)" in ctx
        assert "2 from volume-anomaly(warn)" in ctx
        assert "Review each independently" in ctx

    def test_single_finding_batch_returns_none(self):
        """Single-finding batch gets no framing (only useful for multi-finding batches)."""
        findings = [_make_finding("f1")]
        ctx = build_batch_context(findings)
        assert ctx is None


class TestRunBatchFraming:
    def test_batch_context_passed_to_runner(self):
        """run_batch passes batch_context kwarg to actor_runner for multi-finding batches."""
        findings = [
            _make_finding("f1", detector="new-actor", severity=Severity.WARN),
            _make_finding("f2", detector="volume-anomaly", severity=Severity.CRITICAL),
        ]

        captured_kwargs: list[dict] = []

        def mock_runner(finding: Finding, **kwargs) -> RunResult:
            captured_kwargs.append(kwargs)
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="test",
                ),
                tokens_used=10,
                iterations=1,
            )

        run_batch(mock_runner, findings, actor_name="triage")

        # Both calls should have received batch_context
        assert len(captured_kwargs) == 2
        for kw in captured_kwargs:
            assert "batch_context" in kw
            assert "You have 2 findings" in kw["batch_context"]

    def test_single_finding_batch_no_context_kwarg(self):
        """run_batch does NOT pass batch_context for single-finding batches."""
        findings = [_make_finding("f1")]

        captured_kwargs: list[dict] = []

        def mock_runner(finding: Finding, **kwargs) -> RunResult:
            captured_kwargs.append(kwargs)
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="test",
                ),
                tokens_used=10,
                iterations=1,
            )

        run_batch(mock_runner, findings)

        assert len(captured_kwargs) == 1
        assert "batch_context" not in captured_kwargs[0]

    def test_batch_feedback_records_use_reduced_weight(self):
        """Batch-generated feedback records must use weight=0.3, not default 1.0."""
        findings = [_make_finding("f1"), _make_finding("f2")]

        def mock_runner(finding: Finding, **kwargs) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason="batch resolved",
                ),
                tokens_used=10,
                iterations=1,
            )

        result = run_batch(mock_runner, findings, actor_name="triage")
        assert len(result.feedback_records) == 2
        for rec in result.feedback_records:
            assert rec.weight == 0.3, f"Batch feedback weight should be 0.3, got {rec.weight}"
            assert rec.source == "batch"
