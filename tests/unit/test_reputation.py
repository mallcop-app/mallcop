"""Unit tests for EntityReputation module."""

from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mallcop.reputation import EntityReputation, EntityScore, ScoreEvent
from mallcop.schemas import Finding, FindingStatus, Severity


def _make_finding(
    severity: Severity = Severity.WARN,
    finding_id: str = "f-001",
    detector: str = "test-detector",
) -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime.now(timezone.utc),
        detector=detector,
        event_ids=["e-001"],
        title="Test finding",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_reputation(tmp_path: Path) -> EntityReputation:
    path = tmp_path / "reputation.jsonl"
    return EntityReputation(path)


class TestScoreInit:
    def test_new_entity_score_is_50(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("user", "admin@example.com")
        assert score.score == 50.0

    def test_new_entity_has_empty_history(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("user", "admin@example.com")
        assert score.history == []

    def test_entity_key_format(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("ip", "10.0.0.1")
        assert score.entity_type == "ip"
        assert score.entity_value == "10.0.0.1"

    def test_different_entity_types_independent(self, tmp_path):
        rep = _make_reputation(tmp_path)
        user_score = rep.get_score("user", "alice@example.com")
        ip_score = rep.get_score("ip", "10.0.0.1")
        assert user_score.score == 50.0
        assert ip_score.score == 50.0


class TestFindingAssociation:
    def test_info_finding_decreases_score_by_5(self, tmp_path):
        rep = _make_reputation(tmp_path)
        finding = _make_finding(Severity.INFO)
        rep.record_finding("user", "admin@example.com", finding)
        score = rep.get_score("user", "admin@example.com")
        assert score.score == pytest.approx(45.0, abs=0.01)

    def test_warn_finding_decreases_score_by_10(self, tmp_path):
        rep = _make_reputation(tmp_path)
        finding = _make_finding(Severity.WARN)
        rep.record_finding("user", "admin@example.com", finding)
        score = rep.get_score("user", "admin@example.com")
        assert score.score == pytest.approx(40.0, abs=0.01)

    def test_critical_finding_decreases_score_by_20(self, tmp_path):
        rep = _make_reputation(tmp_path)
        finding = _make_finding(Severity.CRITICAL)
        rep.record_finding("user", "admin@example.com", finding)
        score = rep.get_score("user", "admin@example.com")
        assert score.score == pytest.approx(30.0, abs=0.01)

    def test_multiple_findings_stack(self, tmp_path):
        rep = _make_reputation(tmp_path)
        rep.record_finding("user", "admin@example.com", _make_finding(Severity.WARN, "f-1"))
        rep.record_finding("user", "admin@example.com", _make_finding(Severity.WARN, "f-2"))
        score = rep.get_score("user", "admin@example.com")
        assert score.score == pytest.approx(30.0, abs=0.01)

    def test_score_floor_is_zero(self, tmp_path):
        rep = _make_reputation(tmp_path)
        for i in range(10):
            rep.record_finding(
                "user", "admin@example.com", _make_finding(Severity.CRITICAL, f"f-{i}")
            )
        score = rep.get_score("user", "admin@example.com")
        assert score.score >= 0.0

    def test_finding_adds_history_event(self, tmp_path):
        rep = _make_reputation(tmp_path)
        finding = _make_finding(Severity.WARN)
        rep.record_finding("user", "admin@example.com", finding)
        score = rep.get_score("user", "admin@example.com")
        assert len(score.history) == 1
        assert score.history[0].delta == -10.0
        assert "finding" in score.history[0].reason


class TestBaselineMatch:
    def test_baseline_match_increases_score(self, tmp_path):
        rep = _make_reputation(tmp_path)
        rep.record_baseline_match("user", "alice@example.com")
        score = rep.get_score("user", "alice@example.com")
        assert score.score == pytest.approx(52.0, abs=0.01)

    def test_baseline_match_adds_history_event(self, tmp_path):
        rep = _make_reputation(tmp_path)
        rep.record_baseline_match("user", "alice@example.com")
        score = rep.get_score("user", "alice@example.com")
        assert len(score.history) == 1
        assert score.history[0].delta == 2.0
        assert "baseline" in score.history[0].reason

    def test_score_ceiling_is_100(self, tmp_path):
        rep = _make_reputation(tmp_path)
        for _ in range(100):
            rep.record_baseline_match("user", "alice@example.com")
        score = rep.get_score("user", "alice@example.com")
        assert score.score <= 100.0


class TestDecay:
    def test_score_above_50_decays_toward_50(self, tmp_path):
        rep = _make_reputation(tmp_path)
        # Manually set a score above 50
        score = rep.get_score("user", "alice@example.com")
        score.score = 80.0
        score.last_updated = datetime.now(timezone.utc) - timedelta(days=30)

        decayed = rep.apply_decay(score)
        # 30-day half-life: 30 days past neutral should halve the deviation
        # deviation = 80 - 50 = 30, half-life 30 days -> after 30 days: 30 * 0.5 = 15
        # new score = 50 + 15 = 65
        assert abs(decayed.score - 65.0) < 0.1

    def test_score_below_50_decays_toward_50(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("user", "bad@example.com")
        score.score = 20.0
        score.last_updated = datetime.now(timezone.utc) - timedelta(days=30)

        decayed = rep.apply_decay(score)
        # deviation = 20 - 50 = -30, after 30 days: -30 * 0.5 = -15
        # new score = 50 - 15 = 35
        assert abs(decayed.score - 35.0) < 0.1

    def test_neutral_score_stays_neutral(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("user", "neutral@example.com")
        score.last_updated = datetime.now(timezone.utc) - timedelta(days=30)

        decayed = rep.apply_decay(score)
        assert decayed.score == 50.0

    def test_no_decay_when_recently_updated(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("user", "alice@example.com")
        score.score = 80.0
        score.last_updated = datetime.now(timezone.utc)

        decayed = rep.apply_decay(score)
        assert abs(decayed.score - 80.0) < 0.01

    def test_decay_adds_history_event_when_significant(self, tmp_path):
        rep = _make_reputation(tmp_path)
        score = rep.get_score("user", "alice@example.com")
        score.score = 80.0
        score.last_updated = datetime.now(timezone.utc) - timedelta(days=30)

        decayed = rep.apply_decay(score)
        assert any(e.reason == "decay" for e in decayed.history)


class TestPersistence:
    def test_save_and_reload(self, tmp_path):
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)
        finding = _make_finding(Severity.WARN)
        rep.record_finding("user", "admin@example.com", finding)
        rep.record_baseline_match("ip", "10.0.0.1")
        rep.save()

        rep2 = EntityReputation(path)
        user_score = rep2.get_score("user", "admin@example.com")
        ip_score = rep2.get_score("ip", "10.0.0.1")

        assert user_score.score == pytest.approx(40.0, abs=0.01)
        assert ip_score.score == pytest.approx(52.0, abs=0.01)

    def test_save_preserves_history(self, tmp_path):
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)
        rep.record_finding("user", "alice@example.com", _make_finding(Severity.CRITICAL))
        rep.save()

        rep2 = EntityReputation(path)
        score = rep2.get_score("user", "alice@example.com")
        assert len(score.history) == 1
        assert score.history[0].delta == -20.0

    def test_empty_file_loads_cleanly(self, tmp_path):
        path = tmp_path / "reputation.jsonl"
        path.touch()
        rep = EntityReputation(path)
        score = rep.get_score("user", "nobody@example.com")
        assert score.score == 50.0

    def test_missing_file_creates_on_save(self, tmp_path):
        path = tmp_path / "sub" / "reputation.jsonl"
        rep = EntityReputation(path)
        rep.record_baseline_match("sa", "my-service-account")
        rep.save()
        assert path.exists()

    def test_save_format_is_jsonl(self, tmp_path):
        path = tmp_path / "reputation.jsonl"
        rep = EntityReputation(path)
        rep.record_baseline_match("user", "alice@example.com")
        rep.record_baseline_match("ip", "192.168.1.1")
        rep.save()

        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        for line in lines:
            obj = json.loads(line)
            assert "entity_type" in obj
            assert "entity_value" in obj
            assert "score" in obj


class TestEnrichFinding:
    def test_enrich_adds_reputation_metadata(self, tmp_path):
        rep = _make_reputation(tmp_path)
        # Give "admin@example.com" a low score
        rep.record_finding(
            "user", "admin@example.com", _make_finding(Severity.CRITICAL, "f-prev")
        )

        finding = _make_finding(Severity.WARN, "f-new")
        finding.metadata["actor"] = "admin@example.com"
        finding.metadata["actor_type"] = "user"

        enriched = rep.enrich_finding(finding)
        assert "reputation" in enriched.metadata

    def test_enrich_includes_score_value(self, tmp_path):
        rep = _make_reputation(tmp_path)
        rep.record_finding(
            "user", "admin@example.com", _make_finding(Severity.CRITICAL, "f-prev")
        )

        finding = _make_finding(Severity.WARN, "f-new")
        finding.metadata["actor"] = "admin@example.com"
        finding.metadata["actor_type"] = "user"

        enriched = rep.enrich_finding(finding)
        rep_meta = enriched.metadata["reputation"]
        assert "score" in rep_meta
        assert rep_meta["score"] == pytest.approx(30.0, abs=0.01)

    def test_enrich_no_actor_returns_finding_unchanged(self, tmp_path):
        rep = _make_reputation(tmp_path)
        finding = _make_finding(Severity.WARN)
        # No actor in metadata
        original_meta = dict(finding.metadata)
        enriched = rep.enrich_finding(finding)
        assert enriched.metadata == original_meta

    def test_enrich_unknown_actor_shows_neutral_score(self, tmp_path):
        rep = _make_reputation(tmp_path)
        finding = _make_finding(Severity.WARN)
        finding.metadata["actor"] = "unknown@example.com"
        finding.metadata["actor_type"] = "user"

        enriched = rep.enrich_finding(finding)
        rep_meta = enriched.metadata["reputation"]
        assert rep_meta["score"] == 50.0
