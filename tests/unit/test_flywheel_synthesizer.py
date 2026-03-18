"""Tests for the Academy Flywheel Synthesizer."""
from __future__ import annotations

import pytest

from mallcop.flywheel.synthesizer import Synthesizer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_capture(**overrides) -> dict:
    """Build a minimal anonymized capture dict for synthesis."""
    base = {
        "capture_id": "syn-test-cap-001",
        "captured_at": "2026-03-17T14:30:22+00:00",
        "mallcop_version": "1.0.0",
        "tenant_id": "abc123",
        "connector": "github",
        "detector": "unusual_timing",
        "failure_mode": "KA",
        "difficulty": "malicious-hard",
        "finding_raw": {
            "id": "f1",
            "actor": "user_A",
            "repo": "repo_1",
            "org": "org_ALPHA",
            "severity": "warn",
        },
        "events_raw": [
            {
                "id": "e1",
                "actor": "user_A",
                "timestamp": "2026-01-15T09:00:00Z",
                "event_type": "push",
            },
            {
                "id": "e2",
                "actor": "user_A",
                "timestamp": "2026-01-15T09:01:00Z",
                "event_type": "push",
            },
            {
                "id": "e3",
                "actor": "user_A",
                "timestamp": "2026-01-15T09:02:00Z",
                "event_type": "push",
            },
        ],
        "baseline_raw": {
            "known_entities": ["user_A", "user_B"],
            "actor_frequency": {"user_A": 42},
        },
        "connector_tool_calls": [
            {
                "tool": "list_commits",
                "args_schema": {"repo": "repo_1"},
                "response_raw": {"commits": []},
            }
        ],
        "actor_chain": {
            "triage_action": "escalated",
            "chain_action": "escalated",
            "chain_reason": "Activity at unusual hours suggests account compromise.",
            "llm_calls": [],
            "total_tokens": 800,
        },
        "human_override": None,
        "confidence_score": 0.93,
        "anonymization_validated": True,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# ID format
# ---------------------------------------------------------------------------

class TestSynthesizerId:
    def test_id_starts_with_syn_prefix(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert result["id"].startswith("SYN-")

    def test_id_contains_detector_name(self):
        capture = _make_capture(detector="new_external_access")
        result = Synthesizer().synthesize(capture)
        assert "new_external_access" in result["id"] or "new-external-access" in result["id"]

    def test_id_contains_date_component(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        # Should contain a date like 2026-03-17 or 20260317
        assert "2026" in result["id"]

    def test_id_contains_hash_component(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        # id format: SYN-{detector}-{date}-{hash[:6]}
        parts = result["id"].split("-")
        assert len(parts) >= 4  # SYN, detector, date, hash

    def test_id_is_deterministic_for_same_capture(self):
        capture = _make_capture()
        result1 = Synthesizer().synthesize(capture)
        result2 = Synthesizer().synthesize(capture)
        assert result1["id"] == result2["id"]

    def test_different_captures_produce_different_ids(self):
        c1 = _make_capture(capture_id="cap-001")
        c2 = _make_capture(capture_id="cap-002")
        r1 = Synthesizer().synthesize(c1)
        r2 = Synthesizer().synthesize(c2)
        assert r1["id"] != r2["id"]


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

class TestSynthesizerTags:
    def test_tags_contains_synthetic(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert "synthetic" in result["tags"]

    def test_tags_contains_needs_review(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert "needs-review" in result["tags"]

    def test_tags_is_list(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert isinstance(result["tags"], list)


# ---------------------------------------------------------------------------
# Schema fields
# ---------------------------------------------------------------------------

class TestSynthesizerSchema:
    def test_output_has_required_top_level_fields(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        for field in ["id", "failure_mode", "detector", "category", "difficulty",
                      "finding", "events", "baseline", "expected", "tags"]:
            assert field in result, f"Missing field: {field}"

    def test_finding_maps_from_finding_raw(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert result["finding"] == capture["finding_raw"]

    def test_events_maps_from_events_raw(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert isinstance(result["events"], list)
        assert len(result["events"]) == len(capture["events_raw"])

    def test_baseline_maps_from_baseline_raw(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        assert result["baseline"] == capture["baseline_raw"]

    def test_detector_field_matches_capture(self):
        capture = _make_capture(detector="brute_force")
        result = Synthesizer().synthesize(capture)
        assert result["detector"] == "brute_force"

    def test_failure_mode_field_matches_capture(self):
        capture = _make_capture(failure_mode="AE")
        result = Synthesizer().synthesize(capture)
        assert result["failure_mode"] == "AE"

    def test_difficulty_field_matches_capture(self):
        capture = _make_capture(difficulty="benign-obvious")
        result = Synthesizer().synthesize(capture)
        assert result["difficulty"] == "benign-obvious"

    def test_connector_tools_included_when_present(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        # connector_tools is optional but should be present when tool_calls exist
        assert "connector_tools" in result

    def test_category_set_from_connector(self):
        capture = _make_capture(connector="github")
        result = Synthesizer().synthesize(capture)
        assert "category" in result
        assert result["category"]  # non-empty


# ---------------------------------------------------------------------------
# Timestamps anchored to 2026-01-15T09:00:00Z
# ---------------------------------------------------------------------------

class TestSynthesizerTimestamps:
    def test_first_event_timestamp_anchored_to_reference(self):
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        # First event should be anchored at or near 2026-01-15T09:00:00Z
        first_ts = result["events"][0]["timestamp"]
        assert "2026-01-15" in first_ts

    def test_relative_timing_preserved(self):
        """Events separated by 60s in original should still be 60s apart."""
        from datetime import datetime, timezone
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        events = result["events"]
        assert len(events) >= 2
        t0 = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(events[1]["timestamp"].replace("Z", "+00:00"))
        delta = (t1 - t0).total_seconds()
        # Original events are 60s apart
        assert abs(delta - 60.0) < 1.0


# ---------------------------------------------------------------------------
# Expected field construction
# ---------------------------------------------------------------------------

class TestSynthesizerExpected:
    def test_expected_chain_action_from_human_override_when_present(self):
        capture = _make_capture(
            human_override="dismiss",
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = Synthesizer().synthesize(capture)
        assert result["expected"]["chain_action"] == "dismiss"

    def test_expected_chain_action_from_actor_chain_when_no_override_and_high_confidence(self):
        capture = _make_capture(
            human_override=None,
            confidence_score=0.93,
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = Synthesizer().synthesize(capture)
        assert result["expected"]["chain_action"] == "escalated"

    def test_expected_triage_action_from_human_override_when_present(self):
        capture = _make_capture(
            human_override="dismiss",
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Reason",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = Synthesizer().synthesize(capture)
        assert result["expected"]["triage_action"] == "dismiss"

    def test_expected_ground_truth_synthesized_from_chain_reason(self):
        capture = _make_capture(
            actor_chain={
                "triage_action": "escalated",
                "chain_action": "escalated",
                "chain_reason": "Activity at unusual hours.",
                "llm_calls": [],
                "total_tokens": 500,
            },
        )
        result = Synthesizer().synthesize(capture)
        assert "ground_truth" in result
        assert result["ground_truth"]["expected_conclusion"]


# ---------------------------------------------------------------------------
# YAML-serializable output
# ---------------------------------------------------------------------------

class TestSynthesizerYamlSerializable:
    def test_output_is_yaml_serializable(self):
        import yaml
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        # Should not raise
        yaml_str = yaml.dump(result, allow_unicode=True)
        assert yaml_str

    def test_output_roundtrips_through_yaml(self):
        import yaml
        capture = _make_capture()
        result = Synthesizer().synthesize(capture)
        yaml_str = yaml.dump(result, allow_unicode=True)
        loaded = yaml.safe_load(yaml_str)
        assert loaded["id"] == result["id"]
        assert loaded["tags"] == result["tags"]
