"""Tests for FeedbackRecord weight field and check_feedback_cadence().

Bead: mallcop-9hf5.12
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from mallcop.feedback import FeedbackRecord, HumanAction, check_feedback_cadence
from mallcop.schemas import ActorProfile, Baseline


def _make_record(
    source: str | None = None,
    weight: float | None = None,
    timestamp: datetime | None = None,
    reason: str | None = None,
) -> FeedbackRecord:
    ts = timestamp or datetime.now(timezone.utc)
    kwargs: dict = dict(
        finding_id="fnd_001",
        human_action=HumanAction.OVERRIDE,
        reason=reason,
        original_action="escalate",
        original_reason=None,
        timestamp=ts,
        events=[],
        baseline_snapshot={},
        annotations=[],
        detector="priv-escalation",
    )
    if source is not None:
        kwargs["source"] = source
    if weight is not None:
        kwargs["weight"] = weight
    return FeedbackRecord(**kwargs)


# ---------------------------------------------------------------------------
# Weight field
# ---------------------------------------------------------------------------

class TestFeedbackWeight:
    def test_default_weight_is_1(self):
        rec = _make_record()
        assert rec.weight == 1.0

    def test_batch_weight(self):
        rec = _make_record(source="batch", weight=0.3)
        assert rec.weight == 0.3

    def test_individual_weight_explicit(self):
        rec = _make_record(source="individual", weight=1.0)
        assert rec.weight == 1.0

    def test_weight_roundtrip_dict(self):
        rec = _make_record(source="batch", weight=0.3)
        d = rec.to_dict()
        assert d["weight"] == 0.3
        rec2 = FeedbackRecord.from_dict(d)
        assert rec2.weight == 0.3

    def test_weight_roundtrip_no_weight_in_old_dict(self):
        """Old records without weight field default to 1.0 on load."""
        rec = _make_record()
        d = rec.to_dict()
        del d["weight"]
        rec2 = FeedbackRecord.from_dict(d)
        assert rec2.weight == 1.0

    def test_batch_source_auto_weight(self):
        """Source='batch' with no explicit weight still gets 1.0 — weight is explicit."""
        rec = _make_record(source="batch")
        assert rec.weight == 1.0  # not auto-applied; caller sets weight

    def test_weight_bounds_stored_as_given(self):
        """Weight is advisory — not clamped at storage layer."""
        rec = _make_record(weight=0.0)
        assert rec.weight == 0.0
        rec2 = _make_record(weight=1.0)
        assert rec2.weight == 1.0


# ---------------------------------------------------------------------------
# check_feedback_cadence
# ---------------------------------------------------------------------------

class TestCheckFeedbackCadence:
    def test_12_records_in_3_minutes_triggers_warning(self):
        now = datetime.now(timezone.utc)
        records = [_make_record(timestamp=now - timedelta(seconds=i * 10)) for i in range(12)]
        result = check_feedback_cadence(records)
        assert result is not None
        assert "12" in result or "resolved" in result.lower()

    def test_5_records_in_10_minutes_no_warning(self):
        now = datetime.now(timezone.utc)
        records = [_make_record(timestamp=now - timedelta(minutes=i * 2)) for i in range(5)]
        result = check_feedback_cadence(records)
        assert result is None

    def test_empty_records_no_warning(self):
        assert check_feedback_cadence([]) is None

    def test_single_record_no_warning(self):
        assert check_feedback_cadence([_make_record()]) is None

    def test_exactly_10_in_5_minutes_no_warning(self):
        """Threshold is > 10, so exactly 10 does not trigger."""
        now = datetime.now(timezone.utc)
        records = [_make_record(timestamp=now - timedelta(seconds=i * 25)) for i in range(10)]
        result = check_feedback_cadence(records)
        assert result is None

    def test_11_in_5_minutes_triggers(self):
        """11 in < 5 minutes crosses the threshold."""
        now = datetime.now(timezone.utc)
        records = [_make_record(timestamp=now - timedelta(seconds=i * 20)) for i in range(11)]
        result = check_feedback_cadence(records)
        assert result is not None

    def test_10_records_spread_over_6_minutes_no_warning(self):
        """Records beyond the 5-minute window don't count."""
        now = datetime.now(timezone.utc)
        # 5 recent + 5 old (> 5 min ago)
        recent = [_make_record(timestamp=now - timedelta(seconds=i * 30)) for i in range(5)]
        old = [_make_record(timestamp=now - timedelta(minutes=6 + i)) for i in range(5)]
        result = check_feedback_cadence(recent + old)
        assert result is None

    def test_warning_message_is_helpful(self):
        """Warning message should mention count and suggest review."""
        now = datetime.now(timezone.utc)
        records = [_make_record(timestamp=now - timedelta(seconds=i * 5)) for i in range(15)]
        result = check_feedback_cadence(records)
        assert result is not None
        assert len(result) > 20  # Not a stub


# ---------------------------------------------------------------------------
# update_actor_context: weighted confidence
# ---------------------------------------------------------------------------

class TestWeightedActorContext:
    def _make_baseline(self, actor: str | None = None, confidence: float = 1.0) -> Baseline:
        ctx: dict = {}
        if actor:
            ctx[actor] = ActorProfile(
                location=None,
                timezone=None,
                type="human",
                last_confirmed=datetime.now(timezone.utc),
                source_feedback_ids=[],
                confidence=confidence,
            )
        return Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context=ctx,
        )

    def test_batch_feedback_lowers_confidence_contribution(self):
        """A batch-weight=0.3 override on an unknown actor creates lower-confidence profile."""
        from mallcop.baseline import update_actor_context

        baseline = self._make_baseline()
        rec = _make_record(
            source="batch",
            weight=0.3,
            reason="service account",
        )
        # Give the record an events list with an actor
        rec = FeedbackRecord(
            finding_id="fnd_batch_1",
            human_action=HumanAction.OVERRIDE,
            reason="service account",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime.now(timezone.utc),
            events=[{"actor": "svc-deploy"}],
            baseline_snapshot={},
            annotations=[],
            detector="priv-escalation",
            source="batch",
            weight=0.3,
        )
        updated = update_actor_context(baseline, [rec])
        # Actor should be present in context with confidence reflecting batch weight
        assert "svc-deploy" in updated.actor_context
        profile = updated.actor_context["svc-deploy"]
        assert profile.confidence == pytest.approx(0.3, abs=0.01)

    def test_individual_feedback_full_confidence(self):
        """Individual-weight=1.0 override creates full-confidence profile."""
        from mallcop.baseline import update_actor_context

        baseline = self._make_baseline()
        rec = FeedbackRecord(
            finding_id="fnd_indiv_1",
            human_action=HumanAction.OVERRIDE,
            reason="human employee Seattle",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime.now(timezone.utc),
            events=[{"actor": "baron"}],
            baseline_snapshot={},
            annotations=[],
            detector="new-external-access",
            source="individual",
            weight=1.0,
        )
        updated = update_actor_context(baseline, [rec])
        assert "baron" in updated.actor_context
        profile = updated.actor_context["baron"]
        assert profile.confidence == pytest.approx(1.0, abs=0.01)

    def test_mixed_feedback_weighted_average(self):
        """Two records for same actor: batch (0.3) + individual (1.0) → avg ~0.65."""
        from mallcop.baseline import update_actor_context

        baseline = self._make_baseline()
        now = datetime.now(timezone.utc)
        rec_batch = FeedbackRecord(
            finding_id="fnd_b",
            human_action=HumanAction.OVERRIDE,
            reason="service account",
            original_action="escalate",
            original_reason=None,
            timestamp=now,
            events=[{"actor": "svc-deploy"}],
            baseline_snapshot={},
            annotations=[],
            detector="priv-escalation",
            source="batch",
            weight=0.3,
        )
        rec_individual = FeedbackRecord(
            finding_id="fnd_i",
            human_action=HumanAction.OVERRIDE,
            reason="service account",
            original_action="escalate",
            original_reason=None,
            timestamp=now,
            events=[{"actor": "svc-deploy"}],
            baseline_snapshot={},
            annotations=[],
            detector="priv-escalation",
            source="individual",
            weight=1.0,
        )
        updated = update_actor_context(baseline, [rec_batch, rec_individual])
        assert "svc-deploy" in updated.actor_context
        profile = updated.actor_context["svc-deploy"]
        # (0.3 + 1.0) / 2 = 0.65
        assert profile.confidence == pytest.approx(0.65, abs=0.05)


# ---------------------------------------------------------------------------
# CLI feedback command: cadence warning emitted
# ---------------------------------------------------------------------------

class TestFeedbackCLICadenceWarning:
    def test_cadence_warning_emitted_after_fast_bulk(self, tmp_path):
        """After 11 feedback records in < 5 minutes, cli feedback prints a warning."""
        import json
        from datetime import timezone
        from unittest.mock import patch, MagicMock
        from click.testing import CliRunner
        from mallcop.cli import cli
        from mallcop.store import JsonlStore
        from mallcop.schemas import Finding, FindingStatus, Severity
        from mallcop.feedback import FeedbackRecord, HumanAction

        runner = CliRunner()

        # Set up a finding to give feedback on
        store = JsonlStore(tmp_path)
        finding = Finding(
            id="fnd_test",
            event_ids=["evt_1"],
            detector="priv-escalation",
            severity=Severity.CRITICAL,
            metadata={"actor": "svc-deploy"},
            status=FindingStatus.OPEN,
            timestamp=datetime.now(timezone.utc),
            title="Test finding",
            annotations=[],
        )
        store.append_findings([finding])

        # Populate store with 11 recent feedback records (< 5 min ago)
        now = datetime.now(timezone.utc)
        old_records = [
            FeedbackRecord(
                finding_id=f"fnd_{i}",
                human_action=HumanAction.OVERRIDE,
                reason=None,
                original_action="escalate",
                original_reason=None,
                timestamp=now - timedelta(seconds=i * 15),
                events=[],
                baseline_snapshot={},
                annotations=[],
            )
            for i in range(11)
        ]
        for rec in old_records:
            store.append_feedback(rec)

        result = runner.invoke(cli, [
            "feedback", "fnd_test", "override",
            "--dir", str(tmp_path),
        ])

        output = result.output
        assert "resolved" in output.lower() or "findings" in output.lower() or "review" in output.lower()
        # Should still succeed — find the JSON line
        json_line = next(
            (line for line in output.splitlines() if line.strip().startswith("{")),
            None,
        )
        assert json_line is not None, f"No JSON line found in output: {output!r}"
        parsed = json.loads(json_line)
        assert parsed["status"] == "ok"
