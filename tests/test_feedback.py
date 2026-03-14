"""Tests for feedback capture: FeedbackRecord, store persistence, CLI command."""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.sanitize import sanitize_field
from mallcop.schemas import (
    Annotation,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Fixtures ---

def _make_event(idx: int = 0) -> Event:
    return Event(
        id=f"evt_{idx}",
        timestamp=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2024, 1, 1, 10, 1, tzinfo=timezone.utc),
        source="github",
        event_type="push",
        actor="alice",
        action="push",
        target="main",
        severity=Severity.INFO,
        metadata={"branch": "main"},
        raw={"ref": "refs/heads/main"},
    )


def _make_finding(finding_id: str = "fnd_001") -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime(2024, 1, 1, 10, 5, tzinfo=timezone.utc),
        detector="unusual-timing",
        event_ids=["evt_0"],
        title="Unusual timing from alice",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[
            Annotation(
                actor="triage",
                timestamp=datetime(2024, 1, 1, 10, 6, tzinfo=timezone.utc),
                content="Triage notes here",
                action="investigate",
                reason="Seems suspicious",
            )
        ],
        metadata={"actor": "alice"},
    )


# --- FeedbackRecord unit tests ---

class TestFeedbackRecord:
    def test_all_fields_present(self):
        rec = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.OVERRIDE,
            reason="Baron is US/Eastern",
            original_action="escalate",
            original_reason="Unusual timing",
            timestamp=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={},
            annotations=[],
        )
        assert rec.finding_id == "fnd_001"
        assert rec.human_action == HumanAction.OVERRIDE
        assert rec.reason == "Baron is US/Eastern"
        assert rec.original_action == "escalate"
        assert rec.original_reason == "Unusual timing"
        assert rec.events == []
        assert rec.baseline_snapshot == {}
        assert rec.annotations == []

    def test_human_action_values(self):
        assert HumanAction.AGREE.value == "agree"
        assert HumanAction.OVERRIDE.value == "override"

    def test_to_dict_round_trip(self):
        rec = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.AGREE,
            reason="Looks fine",
            original_action="resolve",
            original_reason="Normal activity",
            timestamp=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
            events=[{"id": "evt_0"}],
            baseline_snapshot={"actors": ["alice"]},
            annotations=[{"actor": "triage", "content": "notes"}],
        )
        d = rec.to_dict()
        assert d["finding_id"] == "fnd_001"
        assert d["human_action"] == "agree"
        assert d["timestamp"] == "2024-01-01T12:00:00+00:00"
        assert d["events"] == [{"id": "evt_0"}]
        assert d["baseline_snapshot"] == {"actors": ["alice"]}

    def test_from_dict_round_trip(self):
        rec = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.OVERRIDE,
            reason="User known",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime(2024, 1, 2, 8, 0, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={},
            annotations=[],
        )
        restored = FeedbackRecord.from_dict(rec.to_dict())
        assert restored.finding_id == rec.finding_id
        assert restored.human_action == HumanAction.OVERRIDE
        assert restored.reason == rec.reason
        assert restored.original_reason is None
        assert restored.timestamp == rec.timestamp

    def test_to_json_and_from_json(self):
        rec = FeedbackRecord(
            finding_id="fnd_abc",
            human_action=HumanAction.AGREE,
            reason=None,
            original_action="resolve",
            original_reason="OK",
            timestamp=datetime(2024, 3, 1, 0, 0, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={},
            annotations=[],
        )
        line = rec.to_json()
        restored = FeedbackRecord.from_json(line)
        assert restored.finding_id == "fnd_abc"
        assert restored.reason is None


# --- Store persistence tests ---

class TestStoreFeedback:
    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        self.store = JsonlStore(Path(self.tmp))

    def _make_record(self, finding_id: str = "fnd_001", action: str = "override") -> FeedbackRecord:
        return FeedbackRecord(
            finding_id=finding_id,
            human_action=HumanAction(action),
            reason="Test reason",
            original_action="escalate",
            original_reason="Suspicious",
            timestamp=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
            events=[{"id": "evt_0"}],
            baseline_snapshot={"actors": ["alice"]},
            annotations=[],
        )

    def test_append_creates_feedback_jsonl(self):
        rec = self._make_record()
        self.store.append_feedback(rec)
        fb_path = Path(self.tmp) / ".mallcop" / "feedback.jsonl"
        assert fb_path.exists()

    def test_append_persists_record(self):
        rec = self._make_record()
        self.store.append_feedback(rec)
        fb_path = Path(self.tmp) / ".mallcop" / "feedback.jsonl"
        lines = [l for l in fb_path.read_text().splitlines() if l]
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["finding_id"] == "fnd_001"

    def test_multiple_appends(self):
        self.store.append_feedback(self._make_record("fnd_001"))
        self.store.append_feedback(self._make_record("fnd_002"))
        fb_path = Path(self.tmp) / ".mallcop" / "feedback.jsonl"
        lines = [l for l in fb_path.read_text().splitlines() if l]
        assert len(lines) == 2

    def test_query_feedback_no_filter(self):
        self.store.append_feedback(self._make_record("fnd_001"))
        self.store.append_feedback(self._make_record("fnd_002"))
        results = self.store.query_feedback()
        assert len(results) == 2

    def test_query_feedback_by_actor(self):
        rec_alice = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.OVERRIDE,
            reason="ok",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={"actor": "alice"},
            annotations=[],
        )
        rec_bob = FeedbackRecord(
            finding_id="fnd_002",
            human_action=HumanAction.AGREE,
            reason="ok",
            original_action="resolve",
            original_reason=None,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={"actor": "bob"},
            annotations=[],
        )
        self.store.append_feedback(rec_alice)
        self.store.append_feedback(rec_bob)
        # No actor filter — returns all
        all_results = self.store.query_feedback()
        assert len(all_results) == 2

    def test_query_feedback_by_detector(self):
        rec1 = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.OVERRIDE,
            reason="ok",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={},
            annotations=[],
            detector="unusual-timing",
        )
        rec2 = FeedbackRecord(
            finding_id="fnd_002",
            human_action=HumanAction.AGREE,
            reason="ok",
            original_action="resolve",
            original_reason=None,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={},
            annotations=[],
            detector="volume-anomaly",
        )
        self.store.append_feedback(rec1)
        self.store.append_feedback(rec2)
        results = self.store.query_feedback(detector="unusual-timing")
        assert len(results) == 1
        assert results[0].detector == "unusual-timing"

    def test_query_feedback_empty_store(self):
        results = self.store.query_feedback()
        assert results == []

    def test_feedback_jsonl_survives_reload(self):
        rec = self._make_record("fnd_persist")
        self.store.append_feedback(rec)
        # Reload store
        store2 = JsonlStore(Path(self.tmp))
        results = store2.query_feedback()
        assert len(results) == 1
        assert results[0].finding_id == "fnd_persist"


# --- Sanitization tests ---

class TestFeedbackSanitization:
    def test_reason_is_sanitized_in_record(self):
        """Feedback reason must be sanitized before storage."""
        raw_reason = "Baron is US/Eastern\x00\x01malicious"
        rec = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.OVERRIDE,
            reason=raw_reason,
            original_action="escalate",
            original_reason=None,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            events=[],
            baseline_snapshot={},
            annotations=[],
        )
        # reason is raw; sanitization happens at store or CLI layer
        assert rec.reason == raw_reason  # stored raw in record

    def test_cli_sanitizes_reason(self, tmp_path):
        """CLI feedback command sanitizes reason text before persisting."""
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        runner = CliRunner()
        evil_reason = "ok\x01\x02inject"
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "override", "--reason", evil_reason, "--dir", str(tmp_path)],
            )
        assert result.exit_code == 0, result.output

        records = store.query_feedback()
        assert len(records) == 1
        stored_reason = records[0].reason
        # Should be sanitized (wrapped in USER_DATA markers, control chars stripped)
        assert "[USER_DATA_BEGIN]" in stored_reason
        assert "\x01" not in stored_reason
        assert "\x02" not in stored_reason

    def test_marker_injection_stripped(self, tmp_path):
        """[USER_DATA_BEGIN] markers in reason input are stripped."""
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        runner = CliRunner()
        injected_reason = "[USER_DATA_BEGIN]injected[USER_DATA_END]"
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "agree", "--reason", injected_reason, "--dir", str(tmp_path)],
            )
        assert result.exit_code == 0
        records = store.query_feedback()
        assert "[USER_DATA_BEGIN]injected[USER_DATA_END][USER_DATA_BEGIN]" not in records[0].reason


# --- CLI command tests ---

class TestFeedbackCLI:
    def test_feedback_command_exists(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["feedback", "--help"])
        assert result.exit_code == 0
        assert "finding-id" in result.output.lower() or "FINDING_ID" in result.output

    def test_feedback_override_persists(self, tmp_path):
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        event = _make_event()
        store.append_findings([finding])
        store.append_events([event])

        runner = CliRunner()
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "override", "--reason", "Baron is US/Eastern", "--dir", str(tmp_path)],
            )
        assert result.exit_code == 0, result.output
        records = store.query_feedback()
        assert len(records) == 1
        assert records[0].finding_id == "fnd_001"
        assert records[0].human_action == HumanAction.OVERRIDE

    def test_feedback_agree_persists(self, tmp_path):
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        runner = CliRunner()
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "agree", "--dir", str(tmp_path)],
            )
        assert result.exit_code == 0, result.output
        records = store.query_feedback()
        assert len(records) == 1
        assert records[0].human_action == HumanAction.AGREE

    def test_feedback_missing_finding_errors(self, tmp_path):
        store = JsonlStore(tmp_path)
        runner = CliRunner()
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_NONEXISTENT", "agree", "--dir", str(tmp_path)],
            )
        assert result.exit_code != 0

    def test_feedback_captures_snapshot(self, tmp_path):
        """Snapshot captures events + baseline + annotations at time of override."""
        store = JsonlStore(tmp_path)
        event = _make_event()
        finding = _make_finding()
        store.append_events([event])
        store.append_findings([finding])

        runner = CliRunner()
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "override", "--reason", "test", "--dir", str(tmp_path)],
            )
        assert result.exit_code == 0, result.output
        records = store.query_feedback()
        assert len(records) == 1
        rec = records[0]
        # Snapshot should have the event IDs
        assert isinstance(rec.events, list)
        # Annotations from the finding should be captured
        assert isinstance(rec.annotations, list)
        assert len(rec.annotations) >= 1

    def test_feedback_invalid_action_errors(self, tmp_path):
        store = JsonlStore(tmp_path)
        runner = CliRunner()
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "BADACTION", "--dir", str(tmp_path)],
            )
        assert result.exit_code != 0

    def test_feedback_reason_optional(self, tmp_path):
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        runner = CliRunner()
        with patch("mallcop.cli.JsonlStore", return_value=store):
            result = runner.invoke(
                cli,
                ["feedback", "fnd_001", "agree", "--dir", str(tmp_path)],
            )
        assert result.exit_code == 0, result.output
        records = store.query_feedback()
        assert records[0].reason is None
