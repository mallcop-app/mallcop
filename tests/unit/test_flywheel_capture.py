"""Tests for ProductionRunCapture — flywheel capture module."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.flywheel.capture import ProductionRunCapture, save_capture, is_capture_enabled


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_capture(**overrides) -> ProductionRunCapture:
    defaults = dict(
        mallcop_version="1.0.0",
        tenant_id="abc123def456",
        connector="github",
        detector="unusual_timing",
        finding_raw={"id": "f1", "severity": "warn", "actor": "alice"},
        events_raw=[{"id": "e1", "type": "push", "actor": "alice"}],
        baseline_raw={"known_entities": ["alice"], "frequency": {"alice": 5}},
        connector_tool_calls=[
            {"tool": "get_commit_history", "args_schema": {}, "response_raw": {"commits": []}}
        ],
        actor_chain={
            "triage_action": "escalated",
            "chain_action": "escalated",
            "chain_reason": "unusual late-night push",
            "llm_calls": [
                {
                    "actor": "triage",
                    "model": "haiku",
                    "tokens": 1200,
                    "latency_ms": 340,
                    "tool_calls": ["get_recent_commits"],
                    "reasoning_excerpt": "push at 03:00 is anomalous",
                }
            ],
            "total_tokens": 2100,
        },
        human_override=None,
        confidence_score=0.87,
    )
    defaults.update(overrides)
    return ProductionRunCapture(**defaults)


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------

class TestProductionRunCaptureFields:
    def test_capture_id_is_uuid4(self):
        cap = _make_capture()
        uid = uuid.UUID(cap.capture_id)
        assert uid.version == 4

    def test_captured_at_is_iso8601(self):
        cap = _make_capture()
        # Must parse without exception
        dt = datetime.fromisoformat(cap.captured_at.replace("Z", "+00:00"))
        assert dt.tzinfo is not None

    def test_required_string_fields(self):
        cap = _make_capture()
        assert isinstance(cap.mallcop_version, str)
        assert isinstance(cap.tenant_id, str)
        assert isinstance(cap.connector, str)
        assert isinstance(cap.detector, str)

    def test_raw_fields_are_dicts_or_lists(self):
        cap = _make_capture()
        assert isinstance(cap.finding_raw, dict)
        assert isinstance(cap.events_raw, list)
        assert isinstance(cap.baseline_raw, dict)
        assert isinstance(cap.connector_tool_calls, list)

    def test_actor_chain_is_dict_with_required_keys(self):
        cap = _make_capture()
        ac = cap.actor_chain
        assert isinstance(ac, dict)
        assert "triage_action" in ac
        assert "chain_action" in ac
        assert "chain_reason" in ac
        assert isinstance(ac["llm_calls"], list)
        assert isinstance(ac["total_tokens"], int)

    def test_human_override_none_by_default(self):
        cap = _make_capture()
        assert cap.human_override is None

    def test_human_override_accepts_string(self):
        cap = _make_capture(human_override="dismiss")
        assert cap.human_override == "dismiss"

    def test_confidence_score_is_float(self):
        cap = _make_capture(confidence_score=0.75)
        assert cap.confidence_score == 0.75

    def test_two_captures_have_distinct_ids(self):
        cap1 = _make_capture()
        cap2 = _make_capture()
        assert cap1.capture_id != cap2.capture_id


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestProductionRunCaptureSerialisation:
    def test_to_dict_contains_all_fields(self):
        cap = _make_capture()
        d = cap.to_dict()
        expected_keys = {
            "capture_id", "captured_at", "mallcop_version", "tenant_id",
            "connector", "detector", "finding_raw", "events_raw",
            "baseline_raw", "connector_tool_calls", "actor_chain",
            "human_override", "confidence_score",
        }
        assert expected_keys <= set(d.keys())

    def test_to_dict_is_json_serializable(self):
        cap = _make_capture()
        serialized = json.dumps(cap.to_dict())
        assert isinstance(serialized, str)

    def test_round_trip(self):
        cap = _make_capture()
        d = cap.to_dict()
        assert d["capture_id"] == cap.capture_id
        assert d["confidence_score"] == cap.confidence_score
        assert d["actor_chain"]["total_tokens"] == 2100


# ---------------------------------------------------------------------------
# File persistence
# ---------------------------------------------------------------------------

class TestSaveCapture:
    def test_save_creates_file(self, tmp_path):
        cap = _make_capture()
        save_capture(cap, base_dir=tmp_path)
        # Should create YYYY-MM subdir
        files = list(tmp_path.glob("**/*.jsonl"))
        assert len(files) == 1

    def test_save_file_in_monthly_subdir(self, tmp_path):
        cap = _make_capture()
        save_capture(cap, base_dir=tmp_path)
        subdirs = [p for p in tmp_path.iterdir() if p.is_dir()]
        assert len(subdirs) == 1
        # Subdir name is YYYY-MM
        name = subdirs[0].name
        assert len(name) == 7
        assert name[4] == "-"

    def test_save_file_is_valid_jsonl(self, tmp_path):
        cap = _make_capture()
        save_capture(cap, base_dir=tmp_path)
        files = list(tmp_path.glob("**/*.jsonl"))
        line = files[0].read_text().strip()
        parsed = json.loads(line)
        assert parsed["capture_id"] == cap.capture_id

    def test_two_captures_produce_two_files(self, tmp_path):
        cap1 = _make_capture()
        cap2 = _make_capture()
        save_capture(cap1, base_dir=tmp_path)
        save_capture(cap2, base_dir=tmp_path)
        files = list(tmp_path.glob("**/*.jsonl"))
        assert len(files) == 2

    def test_save_filename_contains_capture_id(self, tmp_path):
        cap = _make_capture()
        save_capture(cap, base_dir=tmp_path)
        files = list(tmp_path.glob("**/*.jsonl"))
        assert cap.capture_id in files[0].name

    def test_save_creates_parent_dirs(self, tmp_path):
        cap = _make_capture()
        deep_dir = tmp_path / "deep" / "nested"
        save_capture(cap, base_dir=deep_dir)
        files = list(deep_dir.glob("**/*.jsonl"))
        assert len(files) == 1


# ---------------------------------------------------------------------------
# Activation gate
# ---------------------------------------------------------------------------

class TestIsCaptureEnabled:
    def test_disabled_when_no_config(self):
        assert not is_capture_enabled({})

    def test_disabled_when_false(self):
        assert not is_capture_enabled({"capture_telemetry": False})

    def test_enabled_when_true(self):
        assert is_capture_enabled({"capture_telemetry": True})

    def test_disabled_when_key_absent(self):
        assert not is_capture_enabled({"squelch": 5})
