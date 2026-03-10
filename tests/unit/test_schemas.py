"""Tests for core data model: dataclasses, enums, serialization."""

import json
from datetime import datetime, timezone

from mallcop.schemas import (
    Annotation,
    Baseline,
    Checkpoint,
    DiscoveryResult,
    Event,
    Finding,
    FindingStatus,
    PollResult,
    Severity,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TestSeverity:
    def test_values(self) -> None:
        assert Severity.INFO == "info"
        assert Severity.WARN == "warn"
        assert Severity.CRITICAL == "critical"

    def test_is_str(self) -> None:
        assert isinstance(Severity.INFO, str)

    def test_from_string(self) -> None:
        assert Severity("info") is Severity.INFO
        assert Severity("warn") is Severity.WARN
        assert Severity("critical") is Severity.CRITICAL

    def test_invalid_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            Severity("high")


class TestFindingStatus:
    def test_values(self) -> None:
        assert FindingStatus.OPEN == "open"
        assert FindingStatus.RESOLVED == "resolved"
        assert FindingStatus.ACKED == "acked"

    def test_is_str(self) -> None:
        assert isinstance(FindingStatus.OPEN, str)

    def test_invalid_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            FindingStatus("closed")


class TestEvent:
    def _make_event(self, **overrides) -> Event:
        defaults = dict(
            id="evt_abc123",
            timestamp=_utcnow(),
            ingested_at=_utcnow(),
            source="azure",
            event_type="role_assignment",
            actor="admin@example.com",
            action="create",
            target="/subscriptions/123/roleAssignments/456",
            severity=Severity.WARN,
            metadata={"subscription_id": "sub-123"},
            raw={"operationName": "Microsoft.Authorization/roleAssignments/write"},
        )
        defaults.update(overrides)
        return Event(**defaults)

    def test_construct(self) -> None:
        evt = self._make_event()
        assert evt.id == "evt_abc123"
        assert evt.source == "azure"
        assert evt.severity == Severity.WARN

    def test_roundtrip_json(self) -> None:
        evt = self._make_event()
        line = evt.to_json()
        restored = Event.from_json(line)
        assert restored == evt

    def test_json_is_valid_json_string(self) -> None:
        evt = self._make_event()
        data = json.loads(evt.to_json())
        assert data["id"] == "evt_abc123"
        assert data["severity"] == "warn"

    def test_timestamps_roundtrip(self) -> None:
        ts = datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc)
        evt = self._make_event(timestamp=ts, ingested_at=ts)
        restored = Event.from_json(evt.to_json())
        assert restored.timestamp == ts
        assert restored.ingested_at == ts

    def test_metadata_preserved(self) -> None:
        meta = {"nested": {"key": [1, 2, 3]}}
        evt = self._make_event(metadata=meta)
        restored = Event.from_json(evt.to_json())
        assert restored.metadata == meta

    def test_raw_preserved(self) -> None:
        raw = {"big": {"nested": "payload"}, "list": [1, 2]}
        evt = self._make_event(raw=raw)
        restored = Event.from_json(evt.to_json())
        assert restored.raw == raw


class TestAnnotation:
    def _make_annotation(self, **overrides) -> Annotation:
        defaults = dict(
            actor="triage",
            timestamp=_utcnow(),
            content="Unknown actor, not in baseline.",
            action="escalated",
            reason="Actor not recognized",
        )
        defaults.update(overrides)
        return Annotation(**defaults)

    def test_construct(self) -> None:
        ann = self._make_annotation()
        assert ann.actor == "triage"
        assert ann.action == "escalated"

    def test_reason_optional(self) -> None:
        ann = self._make_annotation(reason=None)
        assert ann.reason is None

    def test_roundtrip_json(self) -> None:
        ann = self._make_annotation()
        line = ann.to_json()
        restored = Annotation.from_json(line)
        assert restored == ann

    def test_roundtrip_with_none_reason(self) -> None:
        ann = self._make_annotation(reason=None)
        restored = Annotation.from_json(ann.to_json())
        assert restored.reason is None


class TestFinding:
    def _make_finding(self, **overrides) -> Finding:
        defaults = dict(
            id="fnd_x1y2z3",
            timestamp=_utcnow(),
            detector="new-actor",
            event_ids=["evt_001", "evt_002"],
            title="New admin role assignment",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "admin@unknown.com"},
        )
        defaults.update(overrides)
        return Finding(**defaults)

    def test_construct(self) -> None:
        fnd = self._make_finding()
        assert fnd.id == "fnd_x1y2z3"
        assert fnd.severity == Severity.CRITICAL
        assert fnd.status == FindingStatus.OPEN

    def test_roundtrip_json(self) -> None:
        fnd = self._make_finding()
        line = fnd.to_json()
        restored = Finding.from_json(line)
        assert restored == fnd

    def test_roundtrip_with_annotations(self) -> None:
        ann = Annotation(
            actor="triage",
            timestamp=_utcnow(),
            content="Investigating",
            action="investigating",
            reason=None,
        )
        fnd = self._make_finding(annotations=[ann])
        restored = Finding.from_json(fnd.to_json())
        assert len(restored.annotations) == 1
        assert restored.annotations[0] == ann

    def test_event_ids_preserved(self) -> None:
        fnd = self._make_finding(event_ids=["evt_a", "evt_b", "evt_c"])
        restored = Finding.from_json(fnd.to_json())
        assert restored.event_ids == ["evt_a", "evt_b", "evt_c"]

    def test_severity_in_json(self) -> None:
        fnd = self._make_finding()
        data = json.loads(fnd.to_json())
        assert data["severity"] == "critical"
        assert data["status"] == "open"


class TestCheckpoint:
    def _make_checkpoint(self, **overrides) -> Checkpoint:
        defaults = dict(
            connector="azure",
            value="2026-03-06T00:00:00Z",
            updated_at=_utcnow(),
        )
        defaults.update(overrides)
        return Checkpoint(**defaults)

    def test_construct(self) -> None:
        cp = self._make_checkpoint()
        assert cp.connector == "azure"

    def test_roundtrip_json(self) -> None:
        cp = self._make_checkpoint()
        restored = Checkpoint.from_json(cp.to_json())
        assert restored == cp


class TestDiscoveryResult:
    def _make_discovery(self, **overrides) -> DiscoveryResult:
        defaults = dict(
            available=True,
            resources=["sub-1", "sub-2"],
            suggested_config={"subscription_id": "sub-1"},
            missing_credentials=["client_secret"],
            notes=["Found 2 subscriptions"],
        )
        defaults.update(overrides)
        return DiscoveryResult(**defaults)

    def test_construct(self) -> None:
        dr = self._make_discovery()
        assert dr.available is True
        assert len(dr.resources) == 2

    def test_roundtrip_json(self) -> None:
        dr = self._make_discovery()
        restored = DiscoveryResult.from_json(dr.to_json())
        assert restored == dr

    def test_empty_lists(self) -> None:
        dr = self._make_discovery(
            resources=[], missing_credentials=[], notes=[]
        )
        restored = DiscoveryResult.from_json(dr.to_json())
        assert restored.resources == []
        assert restored.missing_credentials == []
        assert restored.notes == []


class TestPollResult:
    def test_construct(self) -> None:
        evt = Event(
            id="evt_1",
            timestamp=_utcnow(),
            ingested_at=_utcnow(),
            source="azure",
            event_type="login",
            actor="user@example.com",
            action="login",
            target="portal",
            severity=Severity.INFO,
            metadata={},
            raw={},
        )
        cp = Checkpoint(
            connector="azure",
            value="cursor-123",
            updated_at=_utcnow(),
        )
        pr = PollResult(events=[evt], checkpoint=cp)
        assert len(pr.events) == 1
        assert pr.checkpoint.connector == "azure"

    def test_roundtrip_json(self) -> None:
        evt = Event(
            id="evt_1",
            timestamp=_utcnow(),
            ingested_at=_utcnow(),
            source="azure",
            event_type="login",
            actor="user@example.com",
            action="login",
            target="portal",
            severity=Severity.INFO,
            metadata={},
            raw={},
        )
        cp = Checkpoint(
            connector="azure",
            value="cursor-123",
            updated_at=_utcnow(),
        )
        pr = PollResult(events=[evt], checkpoint=cp)
        restored = PollResult.from_json(pr.to_json())
        assert restored == pr
        assert len(restored.events) == 1
        assert restored.checkpoint == cp


class TestBaseline:
    def test_construct(self) -> None:
        bl = Baseline(
            frequency_tables={"azure:login:admin@ex.com:1:2": 5},
            known_entities={"actors": ["admin@ex.com"], "ips": ["1.2.3.4"]},
            relationships={"admin@ex.com": ["/sub/123"]},
        )
        assert bl.frequency_tables["azure:login:admin@ex.com:1:2"] == 5
        assert "admin@ex.com" in bl.known_entities["actors"]

    def test_roundtrip_json(self) -> None:
        bl = Baseline(
            frequency_tables={"key": 10},
            known_entities={"actors": ["a"], "ips": []},
            relationships={"a": ["/r"]},
        )
        restored = Baseline.from_json(bl.to_json())
        assert restored == bl

    def test_empty(self) -> None:
        bl = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
        )
        restored = Baseline.from_json(bl.to_json())
        assert restored == bl
