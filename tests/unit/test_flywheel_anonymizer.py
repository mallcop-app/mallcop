"""Tests for the three-pass flywheel anonymizer."""
from __future__ import annotations

import copy
import json

import pytest

from mallcop.flywheel.anonymizer import Anonymizer, anonymize_capture
from mallcop.flywheel.capture import ProductionRunCapture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_raw_capture(**overrides) -> dict:
    base = {
        "capture_id": "test-cap-001",
        "captured_at": "2026-03-17T14:30:22+00:00",
        "mallcop_version": "1.0.0",
        "tenant_id": "abc123",
        "connector": "github",
        "detector": "unusual_timing",
        "finding_raw": {
            "id": "f1",
            "actor": "alice",
            "repo": "acme-corp/secret-repo",
            "org": "acme-corp",
            "severity": "warn",
            "ip": "203.0.113.42",
            "email": "alice@acme.com",
        },
        "events_raw": [
            {
                "id": "e1",
                "actor": "alice",
                "timestamp": "2026-03-17T14:00:00+00:00",
                "ip": "203.0.113.42",
                "email": "alice@acme.com",
            },
            {
                "id": "e2",
                "actor": "bob",
                "timestamp": "2026-03-17T14:05:00+00:00",
                "ip": "198.51.100.7",
                "email": "bob@acme.com",
            },
        ],
        "baseline_raw": {
            "known_entities": ["alice", "bob", "carol"],
            "actor_frequency": {"alice": 42, "bob": 7},
        },
        "connector_tool_calls": [
            {
                "tool": "get_commit_history",
                "args_schema": {},
                "response_raw": {
                    "author": "alice",
                    "repo": "acme-corp/secret-repo",
                    "message": "A" * 300,  # Long non-security field
                },
            }
        ],
        "actor_chain": {
            "triage_action": "escalated",
            "chain_action": "escalated",
            "chain_reason": "alice made unusual commit to acme-corp/secret-repo",
            "llm_calls": [
                {
                    "actor": "triage",
                    "model": "haiku",
                    "tokens": 1200,
                    "latency_ms": 340,
                    "tool_calls": ["get_recent_commits"],
                    "reasoning_excerpt": "alice pushed to secret-repo at 03:00",
                }
            ],
            "total_tokens": 2100,
        },
        "human_override": None,
        "confidence_score": 0.87,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Pass 1: Identity replacement
# ---------------------------------------------------------------------------

class TestPass1IdentityReplacement:
    def test_username_replaced(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        finding = result["finding_raw"]
        assert finding["actor"] != "alice"
        assert finding["actor"].startswith("user_")

    def test_username_consistent_within_capture(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        # alice appears in finding_raw and events_raw[0]
        actor_in_finding = result["finding_raw"]["actor"]
        actor_in_event = result["events_raw"][0]["actor"]
        assert actor_in_finding == actor_in_event

    def test_two_distinct_users_get_distinct_labels(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        actor_alice = result["events_raw"][0]["actor"]
        actor_bob = result["events_raw"][1]["actor"]
        assert actor_alice != actor_bob

    def test_ip_replaced_with_rfc1918(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        ip_in_finding = result["finding_raw"]["ip"]
        assert ip_in_finding.startswith("10.0.0.")

    def test_same_ip_consistent_within_capture(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert result["finding_raw"]["ip"] == result["events_raw"][0]["ip"]

    def test_different_ips_get_different_labels(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        ip_alice = result["events_raw"][0]["ip"]
        ip_bob = result["events_raw"][1]["ip"]
        assert ip_alice != ip_bob

    def test_email_replaced(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert result["finding_raw"]["email"] == "user@example.com"

    def test_org_replaced(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        org = result["finding_raw"]["org"]
        assert org != "acme-corp"
        assert "org_" in org or org == "org_ALPHA"

    def test_repo_replaced(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        repo = result["finding_raw"]["repo"]
        assert "acme-corp" not in repo
        assert "secret-repo" not in repo

    def test_severity_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert result["finding_raw"]["severity"] == "warn"

    def test_non_identity_fields_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert result["finding_raw"]["id"] == "f1"

    def test_deterministic_within_single_capture(self):
        raw = _make_raw_capture()
        result1 = anonymize_capture(raw)
        result2 = anonymize_capture(copy.deepcopy(raw))
        assert result1["finding_raw"]["actor"] == result2["finding_raw"]["actor"]
        assert result1["finding_raw"]["ip"] == result2["finding_raw"]["ip"]

    def test_timestamps_shifted_preserving_relative_timing(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        events = result["events_raw"]
        # Parse original timestamps
        from datetime import datetime
        orig_0 = datetime.fromisoformat(raw["events_raw"][0]["timestamp"])
        orig_1 = datetime.fromisoformat(raw["events_raw"][1]["timestamp"])
        orig_delta = orig_1 - orig_0

        anon_0 = datetime.fromisoformat(events[0]["timestamp"])
        anon_1 = datetime.fromisoformat(events[1]["timestamp"])
        anon_delta = anon_1 - anon_0

        # Relative timing preserved (same delta)
        assert orig_delta == anon_delta
        # Absolute timestamps shifted (different values)
        assert anon_0 != orig_0


# ---------------------------------------------------------------------------
# Pass 2: Baseline scrubbing
# ---------------------------------------------------------------------------

class TestPass2BaselineScrubbing:
    def test_known_entities_scrubbed(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        known = result["baseline_raw"]["known_entities"]
        assert "alice" not in known
        assert "bob" not in known

    def test_actor_frequency_keys_scrubbed(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        freq = result["baseline_raw"]["actor_frequency"]
        assert "alice" not in freq
        assert "bob" not in freq

    def test_actor_frequency_values_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        freq = result["baseline_raw"]["actor_frequency"]
        values = sorted(freq.values(), reverse=True)
        assert values == [42, 7]

    def test_baseline_structure_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert "known_entities" in result["baseline_raw"]
        assert "actor_frequency" in result["baseline_raw"]


# ---------------------------------------------------------------------------
# Pass 3: Tool response scrubbing
# ---------------------------------------------------------------------------

class TestPass3ToolResponseScrubbing:
    def test_author_in_tool_response_replaced(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        resp = result["connector_tool_calls"][0]["response_raw"]
        assert resp["author"] != "alice"

    def test_long_non_security_field_truncated(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        msg = result["connector_tool_calls"][0]["response_raw"]["message"]
        assert len(msg) <= 200

    def test_tool_name_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert result["connector_tool_calls"][0]["tool"] == "get_commit_history"

    def test_repo_in_tool_response_replaced(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        resp = result["connector_tool_calls"][0]["response_raw"]
        assert "acme-corp" not in str(resp["repo"])
        assert "secret-repo" not in str(resp["repo"])


# ---------------------------------------------------------------------------
# Preserved values
# ---------------------------------------------------------------------------

class TestPreservedValues:
    def test_event_types_preserved(self):
        raw = _make_raw_capture()
        raw["events_raw"][0]["event_type"] = "push"
        result = anonymize_capture(raw)
        assert result["events_raw"][0].get("event_type") == "push"

    def test_action_types_preserved(self):
        raw = _make_raw_capture()
        raw["finding_raw"]["action"] = "force_push"
        result = anonymize_capture(raw)
        assert result["finding_raw"]["action"] == "force_push"

    def test_confidence_score_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        assert result["confidence_score"] == 0.87

    def test_human_override_preserved(self):
        raw = _make_raw_capture()
        raw["human_override"] = "dismiss"
        result = anonymize_capture(raw)
        assert result["human_override"] == "dismiss"

    def test_actor_chain_actions_preserved(self):
        raw = _make_raw_capture()
        result = anonymize_capture(raw)
        ac = result["actor_chain"]
        assert ac["triage_action"] == "escalated"
        assert ac["chain_action"] == "escalated"
        assert ac["total_tokens"] == 2100


# ---------------------------------------------------------------------------
# Anonymizer class API
# ---------------------------------------------------------------------------

class TestAnonymizerClass:
    def test_anonymizer_class_returns_dict(self):
        raw = _make_raw_capture()
        anon = Anonymizer(raw)
        result = anon.run()
        assert isinstance(result, dict)

    def test_anonymizer_identity_map_populated(self):
        raw = _make_raw_capture()
        anon = Anonymizer(raw)
        anon.run()
        assert len(anon.identity_map) > 0

    def test_original_not_mutated(self):
        raw = _make_raw_capture()
        original_actor = raw["finding_raw"]["actor"]
        anonymize_capture(raw)
        assert raw["finding_raw"]["actor"] == original_actor


# ---------------------------------------------------------------------------
# Test environment detection
# ---------------------------------------------------------------------------

class TestTestEnvironmentDetection:
    def test_synthetic_hostname_detected(self):
        from mallcop.flywheel.anonymizer import is_test_environment
        assert is_test_environment("test-host-abc")
        assert is_test_environment("ci-runner-1")
        assert is_test_environment("dev-machine")
        assert is_test_environment("localhost")

    def test_production_hostname_not_detected(self):
        from mallcop.flywheel.anonymizer import is_test_environment
        assert not is_test_environment("prod-server-42")
        assert not is_test_environment("worker-node-3")
