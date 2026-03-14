"""Integration tests for EntityReputation with detect pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.reputation import EntityReputation
from mallcop.schemas import (
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)


def _make_event(
    actor: str = "user@example.com",
    event_id: str = "e-001",
    source: str = "azure",
) -> Event:
    return Event(
        id=event_id,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source=source,
        event_type="login",
        actor=actor,
        action="sign_in",
        target="/subscriptions/abc",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_finding(
    actor: str = "user@example.com",
    finding_id: str = "f-001",
    severity: Severity = Severity.WARN,
) -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime.now(timezone.utc),
        detector="unusual-timing",
        event_ids=["e-001"],
        title="Unusual login timing",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": actor, "actor_type": "user"},
    )


class TestDetectorIntegration:
    def test_reputation_score_query_during_detection(self, tmp_path):
        """Reputation can be loaded and queried in a detection workflow."""
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)

        # Simulate a prior finding against this actor
        prior_finding = _make_finding("bad@example.com", "f-prior", Severity.CRITICAL)
        rep.record_finding("user", "bad@example.com", prior_finding)
        rep.save()

        # Reload (simulating a new detect run)
        rep2 = EntityReputation(path)
        score = rep2.get_score("user", "bad@example.com")
        assert score.score == pytest.approx(30.0, abs=0.01)

    def test_reputation_baseline_match_accumulates(self, tmp_path):
        """Baseline matches accumulate across saves."""
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)
        rep.record_baseline_match("user", "good@example.com")
        rep.record_baseline_match("user", "good@example.com")
        rep.save()

        rep2 = EntityReputation(path)
        score = rep2.get_score("user", "good@example.com")
        assert score.score == pytest.approx(54.0, abs=0.01)


class TestFindingEnrichmentInPipeline:
    def test_enrich_finding_in_detect_pipeline(self, tmp_path):
        """enrich_finding() can be called on detector output."""
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)

        # Pre-seed reputation
        rep.record_finding(
            "user", "suspicious@example.com",
            _make_finding("suspicious@example.com", "f-old", Severity.WARN)
        )

        # Simulate fresh findings from detectors
        new_finding = _make_finding("suspicious@example.com", "f-new", Severity.CRITICAL)
        enriched = rep.enrich_finding(new_finding)

        assert "reputation" in enriched.metadata
        rep_meta = enriched.metadata["reputation"]
        assert rep_meta["score"] == pytest.approx(40.0, abs=0.01)  # After the prior WARN finding

    def test_enrich_finding_does_not_modify_original(self, tmp_path):
        """enrich_finding() returns a new/modified finding without mutating state."""
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)

        finding = _make_finding("user@example.com", "f-001", Severity.WARN)
        original_id = finding.id
        original_detector = finding.detector

        enriched = rep.enrich_finding(finding)

        assert enriched.id == original_id
        assert enriched.detector == original_detector

    def test_multiple_entities_enriched_independently(self, tmp_path):
        """Different actors get independent reputation scores."""
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)

        rep.record_finding(
            "user", "bad@example.com",
            _make_finding("bad@example.com", "f-1", Severity.CRITICAL)
        )
        rep.record_baseline_match("user", "good@example.com")

        bad_finding = _make_finding("bad@example.com", "f-new-1", Severity.WARN)
        good_finding = _make_finding("good@example.com", "f-new-2", Severity.WARN)

        enriched_bad = rep.enrich_finding(bad_finding)
        enriched_good = rep.enrich_finding(good_finding)

        assert enriched_bad.metadata["reputation"]["score"] == pytest.approx(30.0, abs=0.01)
        assert enriched_good.metadata["reputation"]["score"] == pytest.approx(52.0, abs=0.01)
