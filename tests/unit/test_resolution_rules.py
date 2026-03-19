"""Tests for declarative auto-resolution from feedback."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.resolution_rules import (
    ALWAYS_ESCALATE_DETECTORS,
    CONFIRM_THRESHOLD,
    PatternCandidate,
    ResolutionRule,
    auto_escalate_finding,
    auto_resolve_finding,
    check_hard_constraints,
    count_patterns,
    evaluate_rules,
    generate_rules,
    load_rules,
    save_rules,
)
from mallcop.schemas import Baseline, Finding, FindingStatus, Severity


def _make_feedback(
    finding_id: str = "fnd_001",
    action: HumanAction = HumanAction.AGREE,
    detector: str = "volume-anomaly",
    actor: str = "admin-user",
    event_type: str = "add_collaborator",
    target: str = "acme-corp/atom-api",
    weight: float = 1.0,
) -> FeedbackRecord:
    return FeedbackRecord(
        finding_id=finding_id,
        human_action=action,
        reason=None,
        original_action="resolved",
        original_reason="routine",
        timestamp=datetime.now(timezone.utc),
        events=[{
            "id": "evt_001",
            "actor": actor,
            "event_type": event_type,
            "target": target,
            "source": "github",
            "action": event_type,
        }],
        baseline_snapshot={},
        annotations=[],
        detector=detector,
        weight=weight,
    )


def _make_finding(
    finding_id: str = "fnd_test",
    detector: str = "volume-anomaly",
    actor: str = "admin-user",
    event_type: str = "add_collaborator",
    target: str = "acme-corp/atom-api",
) -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime.now(timezone.utc),
        detector=detector,
        event_ids=["evt_001"],
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={
            "actor": actor,
            "event_type": event_type,
            "target": target,
        },
    )


# --- Pattern counting ---


class TestCountPatterns:
    def test_counts_agree_records(self) -> None:
        records = [_make_feedback(finding_id=f"fnd_{i}") for i in range(5)]
        candidates = count_patterns(records)
        assert len(candidates) == 1
        assert candidates[0].count == 5

    def test_ignores_override_records(self) -> None:
        records = [
            _make_feedback(action=HumanAction.AGREE),
            _make_feedback(action=HumanAction.OVERRIDE),
            _make_feedback(action=HumanAction.AGREE),
        ]
        candidates = count_patterns(records)
        assert candidates[0].count == 2

    def test_groups_by_pattern_key(self) -> None:
        records = [
            _make_feedback(actor="admin", event_type="push"),
            _make_feedback(actor="admin", event_type="push"),
            _make_feedback(actor="bot", event_type="deploy"),
        ]
        candidates = count_patterns(records)
        assert len(candidates) == 2
        by_actor = {c.actor: c.count for c in candidates}
        assert by_actor["admin"] == 2
        assert by_actor["bot"] == 1

    def test_wildcards_target_prefix(self) -> None:
        records = [
            _make_feedback(target="acme-corp/repo-a"),
            _make_feedback(target="acme-corp/repo-b"),
        ]
        candidates = count_patterns(records)
        # Both should collapse to same pattern: acme-corp/*
        assert len(candidates) == 1
        assert candidates[0].target_prefix == "acme-corp/*"
        assert candidates[0].count == 2

    def test_never_auto_resolve_privilege(self) -> None:
        records = [_make_feedback(detector="priv-escalation") for _ in range(10)]
        candidates = count_patterns(records)
        assert len(candidates) == 0

    def test_never_auto_resolve_external_access(self) -> None:
        records = [_make_feedback(detector="new-external-access") for _ in range(10)]
        candidates = count_patterns(records)
        assert len(candidates) == 0

    def test_never_auto_resolve_unusual_resource_access(self) -> None:
        records = [_make_feedback(detector="unusual-resource-access") for _ in range(10)]
        candidates = count_patterns(records)
        assert len(candidates) == 0

    def test_confidence_weighting(self) -> None:
        records = [
            _make_feedback(weight=0.3),  # batch
            _make_feedback(weight=0.3),  # batch
            _make_feedback(weight=1.0),  # individual
        ]
        candidates = count_patterns(records)
        assert candidates[0].count == 3
        # weighted_confidence = 0.3 + 0.3 + 1.0 = 1.6
        # confidence = 1.6 / 3 = 0.533
        assert abs(candidates[0].confidence - 0.533) < 0.01

    def test_rejects_broad_wildcard_target(self) -> None:
        records = [_make_feedback(target="*/something") for _ in range(10)]
        candidates = count_patterns(records)
        assert len(candidates) == 0

    def test_rejects_single_char_prefix(self) -> None:
        records = [_make_feedback(target="x/something") for _ in range(10)]
        candidates = count_patterns(records)
        assert len(candidates) == 0

    def test_empty_records(self) -> None:
        assert count_patterns([]) == []


# --- Rule generation ---


class TestGenerateRules:
    def test_generates_rule_above_threshold(self) -> None:
        records = [_make_feedback(finding_id=f"fnd_{i}") for i in range(CONFIRM_THRESHOLD)]
        candidates = count_patterns(records)
        rules = generate_rules(candidates)
        assert len(rules) == 1
        assert rules[0].detector == "volume-anomaly"
        assert rules[0].actor == "admin-user"

    def test_skips_below_threshold(self) -> None:
        records = [_make_feedback(finding_id=f"fnd_{i}") for i in range(CONFIRM_THRESHOLD - 1)]
        candidates = count_patterns(records)
        rules = generate_rules(candidates)
        assert len(rules) == 0

    def test_skips_low_confidence(self) -> None:
        # All batch weight (0.3) → confidence = 0.3 < 0.7 threshold
        records = [_make_feedback(finding_id=f"fnd_{i}", weight=0.3) for i in range(10)]
        candidates = count_patterns(records)
        rules = generate_rules(candidates)
        assert len(rules) == 0

    def test_rule_has_reason_template(self) -> None:
        records = [_make_feedback(finding_id=f"fnd_{i}") for i in range(CONFIRM_THRESHOLD)]
        rules = generate_rules(count_patterns(records))
        assert "admin-user" in rules[0].reason_template
        assert "add_collaborator" in rules[0].reason_template


# --- Rule persistence ---


class TestRulePersistence:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        rules = [ResolutionRule(
            id="auto-test",
            detector="test-detector",
            actor="test-actor",
            event_type="test-action",
            target_prefix="test-target/*",
            reason_template="Test reason",
            source_feedback_count=7,
            confidence=0.85,
        )]
        path = tmp_path / "rules.yaml"
        save_rules(rules, path)
        loaded = load_rules(path)
        assert len(loaded) == 1
        assert loaded[0].id == "auto-test"
        assert loaded[0].detector == "test-detector"
        assert loaded[0].confidence == 0.85

    def test_load_missing_file(self, tmp_path: Path) -> None:
        assert load_rules(tmp_path / "nonexistent.yaml") == []


# --- Rule evaluation ---


class TestEvaluateRules:
    def test_matching_rule_returns_rule(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = _make_finding()
        result = evaluate_rules(finding, [rule])
        assert result is not None
        assert result.id == "auto-test"

    def test_wrong_detector_no_match(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="count-threshold",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = _make_finding()
        assert evaluate_rules(finding, [rule]) is None

    def test_wrong_actor_no_match(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="volume-anomaly",
            actor="other-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = _make_finding()
        assert evaluate_rules(finding, [rule]) is None

    def test_target_wildcard_match(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = _make_finding(target="acme-corp/different-repo")
        assert evaluate_rules(finding, [rule]) is not None

    def test_never_auto_resolve_privilege(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="priv-escalation",
            actor="admin-user",
            event_type="role_grant",
            target_prefix="*",
        )
        finding = _make_finding(detector="priv-escalation", event_type="role_grant")
        assert evaluate_rules(finding, [rule]) is None

    def test_unknown_actor_in_baseline_skips(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["other-user"]},  # admin-user NOT known
            relationships={},
        )
        finding = _make_finding()
        assert evaluate_rules(finding, [rule], baseline=baseline) is None

    def test_known_actor_in_baseline_matches(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["admin-user"]},
            relationships={},
        )
        finding = _make_finding()
        assert evaluate_rules(finding, [rule], baseline=baseline) is not None


# --- Auto-resolve ---


class TestAutoResolve:
    def test_sets_status_resolved(self) -> None:
        rule = ResolutionRule(
            id="auto-test",
            detector="test",
            actor="test",
            event_type="test",
            target_prefix="test",
            reason_template="Auto-resolved for testing",
            confidence=0.9,
            source_feedback_count=7,
        )
        finding = _make_finding()
        result = auto_resolve_finding(finding, rule)
        assert result.status == FindingStatus.RESOLVED
        assert len(result.annotations) == 1
        assert result.annotations[0].action == "resolved"
        assert result.annotations[0].actor == "auto-resolution"
        assert "auto-test" in result.annotations[0].content


# --- End-to-end ---


class TestEndToEnd:
    def test_full_pipeline(self, tmp_path: Path) -> None:
        """feedback → count → generate → save → load → evaluate → resolve"""
        # 5 confirmed-benign feedbacks for same pattern
        records = [_make_feedback(finding_id=f"fnd_{i}") for i in range(5)]

        # Count patterns
        candidates = count_patterns(records)
        assert len(candidates) == 1
        assert candidates[0].meets_threshold

        # Generate rules
        rules = generate_rules(candidates)
        assert len(rules) == 1

        # Save and reload
        path = tmp_path / "rules.yaml"
        save_rules(rules, path)
        loaded = load_rules(path)

        # Evaluate against a new finding with same pattern
        finding = _make_finding(finding_id="fnd_new")
        match = evaluate_rules(finding, loaded)
        assert match is not None

        # Auto-resolve
        resolved = auto_resolve_finding(finding, match)
        assert resolved.status == FindingStatus.RESOLVED

    def test_different_finding_no_match(self, tmp_path: Path) -> None:
        """Rule for one pattern doesn't match a different finding."""
        records = [_make_feedback(finding_id=f"fnd_{i}") for i in range(5)]
        rules = generate_rules(count_patterns(records))

        finding = _make_finding(
            finding_id="fnd_different",
            detector="volume-anomaly",
            actor="other-user",
        )
        assert evaluate_rules(finding, rules) is None


# --- Hard constraints ---


class TestCheckHardConstraints:
    def test_priv_escalation_returns_reason(self) -> None:
        finding = _make_finding(detector="priv-escalation")
        reason = check_hard_constraints(finding)
        assert reason is not None
        assert "priv-escalation" in reason

    def test_injection_probe_returns_reason(self) -> None:
        finding = _make_finding(detector="injection-probe")
        assert check_hard_constraints(finding) is not None

    def test_boundary_violation_returns_reason(self) -> None:
        finding = _make_finding(detector="boundary-violation")
        assert check_hard_constraints(finding) is not None

    def test_log_format_drift_returns_reason(self) -> None:
        finding = _make_finding(detector="log-format-drift")
        assert check_hard_constraints(finding) is not None

    def test_normal_detector_returns_none(self) -> None:
        finding = _make_finding(detector="volume-anomaly")
        assert check_hard_constraints(finding) is None

    def test_unknown_detector_returns_none(self) -> None:
        finding = _make_finding(detector="totally-new-detector")
        assert check_hard_constraints(finding) is None

    def test_all_escalate_detectors_covered(self) -> None:
        for det in ALWAYS_ESCALATE_DETECTORS:
            finding = _make_finding(detector=det)
            assert check_hard_constraints(finding) is not None, f"{det} should trigger hard constraint"


class TestAutoEscalateFinding:
    def test_adds_annotation(self) -> None:
        finding = _make_finding()
        result = auto_escalate_finding(finding, "test reason")
        assert len(result.annotations) == 1

    def test_annotation_actor_is_hard_constraint(self) -> None:
        finding = _make_finding()
        result = auto_escalate_finding(finding, "test reason")
        assert result.annotations[0].actor == "hard-constraint"

    def test_annotation_action_is_escalated(self) -> None:
        finding = _make_finding()
        result = auto_escalate_finding(finding, "test reason")
        assert result.annotations[0].action == "escalated"

    def test_status_stays_open(self) -> None:
        finding = _make_finding()
        result = auto_escalate_finding(finding, "test reason")
        assert result.status == FindingStatus.OPEN


class TestUserDataMarkerStripping:
    """Pattern keys and rule matching must strip USER_DATA markers."""

    def test_pattern_key_strips_markers_from_events(self) -> None:
        """Feedback events with USER_DATA markers produce clean pattern keys."""
        fb = _make_feedback(
            actor="[USER_DATA_BEGIN]admin-user[USER_DATA_END]",
            event_type="[USER_DATA_BEGIN]add_collaborator[USER_DATA_END]",
            target="[USER_DATA_BEGIN]acme-corp/atom-api[USER_DATA_END]",
        )
        patterns = count_patterns([fb])
        assert len(patterns) == 1
        # Key should be clean, no markers
        assert "[USER_DATA" not in patterns[0].key
        assert patterns[0].actor == "admin-user"
        assert patterns[0].event_type == "add_collaborator"

    def test_evaluate_rules_matches_despite_markers_in_metadata(self) -> None:
        """Rules with clean keys match findings whose metadata has USER_DATA markers."""
        rule = ResolutionRule(
            id="rule_1",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
            source_feedback_count=3,
            confidence=0.9,
        )
        finding = _make_finding(
            actor="[USER_DATA_BEGIN]admin-user[USER_DATA_END]",
            event_type="[USER_DATA_BEGIN]add_collaborator[USER_DATA_END]",
            target="[USER_DATA_BEGIN]acme-corp/atom-api[USER_DATA_END]",
        )
        result = evaluate_rules(finding, [rule])
        assert result is not None
        assert result.id == "rule_1"


class TestEvaluateRulesEventFallback:
    """evaluate_rules should fall back to event-level actor/event_type when
    finding.metadata is sparse (most built-in detectors don't populate these)."""

    def _make_sparse_finding(
        self,
        finding_id: str = "fnd_sparse",
        detector: str = "volume-anomaly",
    ) -> Finding:
        """Finding with no actor/event_type in metadata."""
        return Finding(
            id=finding_id,
            timestamp=datetime.now(timezone.utc),
            detector=detector,
            event_ids=["evt_001"],
            title="Sparse finding",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={},  # no actor, no event_type
        )

    def _make_event_obj(
        self,
        actor: str = "admin-user",
        event_type: str = "add_collaborator",
        target: str = "acme-corp/atom-api",
    ):
        from mallcop.schemas import Event, Severity

        return Event(
            id="evt_001",
            timestamp=datetime.now(timezone.utc),
            ingested_at=datetime.now(timezone.utc),
            source="github",
            event_type=event_type,
            actor=actor,
            action="add",
            target=target,
            severity=Severity.WARN,
            metadata={},
            raw={},
        )

    def test_matches_via_event_fallback_when_metadata_empty(self):
        """Rule should match when actor/event_type come from events, not metadata."""
        rule = ResolutionRule(
            id="auto-event-fallback",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = self._make_sparse_finding()
        events = [self._make_event_obj()]

        result = evaluate_rules(finding, [rule], events=events)
        assert result is not None
        assert result.id == "auto-event-fallback"

    def test_no_match_without_events_and_sparse_metadata(self):
        """Without events, sparse metadata should not produce a false match."""
        rule = ResolutionRule(
            id="auto-event-fallback",
            detector="volume-anomaly",
            actor="admin-user",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = self._make_sparse_finding()
        result = evaluate_rules(finding, [rule])
        assert result is None

    def test_metadata_takes_precedence_over_events(self):
        """If metadata has actor, it takes priority; event actor is ignored."""
        rule = ResolutionRule(
            id="meta-priority",
            detector="volume-anomaly",
            actor="meta-actor",
            event_type="add_collaborator",
            target_prefix="acme-corp/*",
        )
        finding = Finding(
            id="fnd_meta",
            timestamp=datetime.now(timezone.utc),
            detector="volume-anomaly",
            event_ids=["evt_001"],
            title="Meta finding",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "meta-actor", "event_type": "add_collaborator",
                       "target": "acme-corp/atom-api"},
        )
        # Event has a DIFFERENT actor that doesn't match the rule
        events = [self._make_event_obj(actor="wrong-actor")]
        result = evaluate_rules(finding, [rule], events=events)
        assert result is not None
