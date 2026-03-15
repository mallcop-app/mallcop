"""Tests for Store ABC and JsonlStore implementation."""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
import yaml

from mallcop.schemas import (
    Annotation,
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore, Store


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    timestamp: datetime | None = None,
    actor: str = "admin@example.com",
    **overrides,
) -> Event:
    defaults = dict(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type="role_assignment",
        actor=actor,
        action="create",
        target="/subscriptions/123/roleAssignments/456",
        severity=Severity.WARN,
        metadata={},
        raw={},
    )
    defaults.update(overrides)
    return Event(**defaults)


def _make_finding(
    id: str = "fnd_001",
    status: FindingStatus = FindingStatus.OPEN,
    severity: Severity = Severity.CRITICAL,
    **overrides,
) -> Finding:
    defaults = dict(
        id=id,
        timestamp=_utcnow(),
        detector="new-actor",
        event_ids=["evt_001"],
        title="New admin role assignment",
        severity=severity,
        status=status,
        annotations=[],
        metadata={},
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestStoreABC:
    def test_is_abstract(self) -> None:
        """Store cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Store()  # type: ignore

    def test_jsonlstore_is_store(self, tmp_path: Path) -> None:
        """JsonlStore is a concrete Store."""
        store = JsonlStore(tmp_path)
        assert isinstance(store, Store)


class TestJsonlStoreEvents:
    def test_append_and_query_events(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        evt = _make_event()
        store.append_events([evt])
        results = store.query_events()
        assert len(results) == 1
        assert results[0].id == "evt_001"

    def test_query_events_by_source(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        e1 = _make_event(id="evt_az", source="azure")
        e2 = _make_event(id="evt_gh", source="github")
        store.append_events([e1, e2])

        azure_events = store.query_events(source="azure")
        assert len(azure_events) == 1
        assert azure_events[0].id == "evt_az"

        github_events = store.query_events(source="github")
        assert len(github_events) == 1
        assert github_events[0].id == "evt_gh"

    def test_query_events_by_actor(self, tmp_path: Path) -> None:
        from mallcop.sanitize import sanitize_field

        store = JsonlStore(tmp_path)
        e1 = _make_event(id="evt_1", actor="alice@ex.com")
        e2 = _make_event(id="evt_2", actor="bob@ex.com")
        store.append_events([e1, e2])

        # Actor is sanitized at ingest, so query must use sanitized value
        results = store.query_events(actor=sanitize_field("alice@ex.com"))
        assert len(results) == 1
        assert results[0].id == "evt_1"

    def test_query_events_since(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        old = _make_event(
            id="evt_old",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        new = _make_event(
            id="evt_new",
            timestamp=datetime(2026, 3, 6, tzinfo=timezone.utc),
        )
        store.append_events([old, new])

        results = store.query_events(since=datetime(2026, 3, 1, tzinfo=timezone.utc))
        assert len(results) == 1
        assert results[0].id == "evt_new"

    def test_query_events_limit(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        events = [_make_event(id=f"evt_{i}") for i in range(10)]
        store.append_events(events)

        results = store.query_events(limit=3)
        assert len(results) == 3

    def test_events_written_to_jsonl(self, tmp_path: Path) -> None:
        """JSONL file exists on disk after append."""
        store = JsonlStore(tmp_path)
        ts = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        evt = _make_event(id="evt_disk", source="azure", timestamp=ts)
        store.append_events([evt])

        jsonl_path = tmp_path / ".mallcop" / "events" / "azure-2026-03.jsonl"
        assert jsonl_path.exists()

        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["id"] == "evt_disk"

    def test_event_partitioning_by_source(self, tmp_path: Path) -> None:
        """Two sources produce two separate JSONL files."""
        store = JsonlStore(tmp_path)
        ts = datetime(2026, 3, 10, tzinfo=timezone.utc)
        e_az = _make_event(id="evt_az", source="azure", timestamp=ts)
        e_gh = _make_event(id="evt_gh", source="github", timestamp=ts)
        store.append_events([e_az, e_gh])

        assert (tmp_path / ".mallcop" / "events" / "azure-2026-03.jsonl").exists()
        assert (tmp_path / ".mallcop" / "events" / "github-2026-03.jsonl").exists()

    def test_event_partitioning_by_month(self, tmp_path: Path) -> None:
        """Events in different months go to different files."""
        store = JsonlStore(tmp_path)
        e_mar = _make_event(
            id="evt_mar",
            source="azure",
            timestamp=datetime(2026, 3, 15, tzinfo=timezone.utc),
        )
        e_apr = _make_event(
            id="evt_apr",
            source="azure",
            timestamp=datetime(2026, 4, 1, tzinfo=timezone.utc),
        )
        store.append_events([e_mar, e_apr])

        mar_path = tmp_path / ".mallcop" / "events" / "azure-2026-03.jsonl"
        apr_path = tmp_path / ".mallcop" / "events" / "azure-2026-04.jsonl"
        assert mar_path.exists()
        assert apr_path.exists()

        mar_data = json.loads(mar_path.read_text().strip())
        assert mar_data["id"] == "evt_mar"

        apr_data = json.loads(apr_path.read_text().strip())
        assert apr_data["id"] == "evt_apr"

    def test_append_multiple_batches(self, tmp_path: Path) -> None:
        """Multiple appends accumulate in the same file."""
        store = JsonlStore(tmp_path)
        ts = datetime(2026, 3, 10, tzinfo=timezone.utc)
        store.append_events([_make_event(id="evt_1", timestamp=ts)])
        store.append_events([_make_event(id="evt_2", timestamp=ts)])

        results = store.query_events()
        assert len(results) == 2

        jsonl_path = tmp_path / ".mallcop" / "events" / "azure-2026-03.jsonl"
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_reload_from_disk(self, tmp_path: Path) -> None:
        """A new JsonlStore loads events written by a previous instance."""
        ts = datetime(2026, 3, 10, tzinfo=timezone.utc)
        store1 = JsonlStore(tmp_path)
        store1.append_events([_make_event(id="evt_persist", timestamp=ts)])

        store2 = JsonlStore(tmp_path)
        results = store2.query_events()
        assert len(results) == 1
        assert results[0].id == "evt_persist"

    def test_github_source_writes_to_github_partition(self, tmp_path: Path) -> None:
        """GitHub events land in events/github-YYYY-MM.jsonl."""
        store = JsonlStore(tmp_path)
        ts = datetime(2026, 3, 20, tzinfo=timezone.utc)
        evt = _make_event(id="evt_gh1", source="github", timestamp=ts)
        store.append_events([evt])

        jsonl_path = tmp_path / ".mallcop" / "events" / "github-2026-03.jsonl"
        assert jsonl_path.exists()
        data = json.loads(jsonl_path.read_text().strip())
        assert data["id"] == "evt_gh1"

    def test_query_events_reads_across_partitions(self, tmp_path: Path) -> None:
        """query_events with no filters returns events from all partition files."""
        store = JsonlStore(tmp_path)
        ts_mar = datetime(2026, 3, 10, tzinfo=timezone.utc)
        ts_apr = datetime(2026, 4, 10, tzinfo=timezone.utc)
        store.append_events([
            _make_event(id="evt_az_mar", source="azure", timestamp=ts_mar),
            _make_event(id="evt_gh_mar", source="github", timestamp=ts_mar),
            _make_event(id="evt_az_apr", source="azure", timestamp=ts_apr),
        ])

        # Reload from disk to prove cross-partition reading works
        store2 = JsonlStore(tmp_path)
        results = store2.query_events()
        assert len(results) == 3
        ids = {r.id for r in results}
        assert ids == {"evt_az_mar", "evt_gh_mar", "evt_az_apr"}

    def test_query_events_source_filter_across_partitions(self, tmp_path: Path) -> None:
        """query_events(source=...) returns correct results across partition files."""
        store = JsonlStore(tmp_path)
        ts = datetime(2026, 3, 10, tzinfo=timezone.utc)
        store.append_events([
            _make_event(id="evt_az", source="azure", timestamp=ts),
            _make_event(id="evt_gh", source="github", timestamp=ts),
        ])

        # Reload and filter
        store2 = JsonlStore(tmp_path)
        az = store2.query_events(source="azure")
        assert len(az) == 1
        assert az[0].id == "evt_az"

        gh = store2.query_events(source="github")
        assert len(gh) == 1
        assert gh[0].id == "evt_gh"

    def test_empty_events_directory_returns_empty(self, tmp_path: Path) -> None:
        """An empty events/ directory yields no events."""
        (tmp_path / ".mallcop" / "events").mkdir(parents=True)
        store = JsonlStore(tmp_path)
        assert store.query_events() == []

    def test_no_events_directory_returns_empty(self, tmp_path: Path) -> None:
        """No events/ directory at all yields no events."""
        store = JsonlStore(tmp_path)
        assert store.query_events() == []


class TestJsonlStoreFindings:
    def test_append_and_query_findings(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        fnd = _make_finding()
        store.append_findings([fnd])

        results = store.query_findings()
        assert len(results) == 1
        assert results[0].id == "fnd_001"

    def test_query_findings_by_status(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        f_open = _make_finding(id="fnd_open", status=FindingStatus.OPEN)
        f_resolved = _make_finding(id="fnd_resolved", status=FindingStatus.RESOLVED)
        store.append_findings([f_open, f_resolved])

        open_results = store.query_findings(status="open")
        assert len(open_results) == 1
        assert open_results[0].id == "fnd_open"

        resolved_results = store.query_findings(status="resolved")
        assert len(resolved_results) == 1
        assert resolved_results[0].id == "fnd_resolved"

    def test_query_findings_by_severity(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        f_crit = _make_finding(id="fnd_crit", severity=Severity.CRITICAL)
        f_warn = _make_finding(id="fnd_warn", severity=Severity.WARN)
        store.append_findings([f_crit, f_warn])

        results = store.query_findings(severity="critical")
        assert len(results) == 1
        assert results[0].id == "fnd_crit"

    def test_update_finding_status(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        fnd = _make_finding(id="fnd_upd", status=FindingStatus.OPEN)
        store.append_findings([fnd])

        store.update_finding("fnd_upd", status=FindingStatus.RESOLVED)
        results = store.query_findings(status="resolved")
        assert len(results) == 1
        assert results[0].id == "fnd_upd"
        assert results[0].status == FindingStatus.RESOLVED

    def test_update_finding_add_annotation(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        fnd = _make_finding(id="fnd_ann")
        store.append_findings([fnd])

        ann = Annotation(
            actor="triage",
            timestamp=_utcnow(),
            content="Investigating",
            action="investigating",
            reason=None,
        )
        store.update_finding("fnd_ann", annotations=[ann])

        results = store.query_findings()
        assert len(results[0].annotations) == 1
        assert results[0].annotations[0].actor == "triage"

    def test_findings_written_to_jsonl(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        fnd = _make_finding()
        store.append_findings([fnd])

        jsonl_path = tmp_path / ".mallcop" / "findings.jsonl"
        assert jsonl_path.exists()
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_update_finding_persists_to_disk(self, tmp_path: Path) -> None:
        """After update_finding, the findings.jsonl reflects the update."""
        store = JsonlStore(tmp_path)
        fnd = _make_finding(id="fnd_persist", status=FindingStatus.OPEN)
        store.append_findings([fnd])

        store.update_finding("fnd_persist", status=FindingStatus.ACKED)

        # Reload from disk
        store2 = JsonlStore(tmp_path)
        results = store2.query_findings(status="acked")
        assert len(results) == 1
        assert results[0].id == "fnd_persist"

    def test_query_findings_by_actor(self, tmp_path: Path) -> None:
        """Filter findings by actor stored in metadata."""
        store = JsonlStore(tmp_path)
        now = _utcnow()
        f1 = _make_finding(id="fnd_a1", metadata={"actor": "alice@example.com"})
        f2 = _make_finding(id="fnd_a2", metadata={"actor": "bob@example.com"})
        f3 = _make_finding(id="fnd_a3", metadata={})
        store.append_findings([f1, f2, f3])

        results = store.query_findings(actor="alice@example.com")
        assert len(results) == 1
        assert results[0].id == "fnd_a1"

    def test_query_findings_by_detector(self, tmp_path: Path) -> None:
        """Filter findings by detector name."""
        store = JsonlStore(tmp_path)
        f1 = _make_finding(id="fnd_d1", detector="new-actor")
        f2 = _make_finding(id="fnd_d2", detector="priv-escalation")
        store.append_findings([f1, f2])

        results = store.query_findings(detector="new-actor")
        assert len(results) == 1
        assert results[0].id == "fnd_d1"

    def test_query_findings_by_since(self, tmp_path: Path) -> None:
        """Filter findings by timestamp >= since."""
        store = JsonlStore(tmp_path)
        old_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        new_time = datetime(2026, 3, 10, tzinfo=timezone.utc)
        f1 = _make_finding(id="fnd_old", timestamp=old_time)
        f2 = _make_finding(id="fnd_new", timestamp=new_time)
        store.append_findings([f1, f2])

        cutoff = datetime(2026, 3, 1, tzinfo=timezone.utc)
        results = store.query_findings(since=cutoff)
        assert len(results) == 1
        assert results[0].id == "fnd_new"

    def test_query_findings_combined_filters(self, tmp_path: Path) -> None:
        """Multiple filter params combine with AND logic."""
        store = JsonlStore(tmp_path)
        now = _utcnow()
        f1 = _make_finding(
            id="fnd_match",
            detector="new-actor",
            metadata={"actor": "alice@example.com"},
            status=FindingStatus.OPEN,
        )
        f2 = _make_finding(
            id="fnd_wrong_det",
            detector="priv-escalation",
            metadata={"actor": "alice@example.com"},
            status=FindingStatus.OPEN,
        )
        f3 = _make_finding(
            id="fnd_wrong_actor",
            detector="new-actor",
            metadata={"actor": "bob@example.com"},
            status=FindingStatus.OPEN,
        )
        store.append_findings([f1, f2, f3])

        results = store.query_findings(
            actor="alice@example.com", detector="new-actor"
        )
        assert len(results) == 1
        assert results[0].id == "fnd_match"


class TestJsonlStoreCheckpoints:
    def test_set_and_get_checkpoint(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        cp = Checkpoint(
            connector="azure",
            value="2026-03-06T00:00:00Z",
            updated_at=_utcnow(),
        )
        store.set_checkpoint(cp)

        result = store.get_checkpoint("azure")
        assert result is not None
        assert result.connector == "azure"
        assert result.value == "2026-03-06T00:00:00Z"

    def test_get_checkpoint_missing(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        result = store.get_checkpoint("nonexistent")
        assert result is None

    def test_checkpoint_overwrite(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        cp1 = Checkpoint(connector="azure", value="v1", updated_at=_utcnow())
        store.set_checkpoint(cp1)

        cp2 = Checkpoint(connector="azure", value="v2", updated_at=_utcnow())
        store.set_checkpoint(cp2)

        result = store.get_checkpoint("azure")
        assert result is not None
        assert result.value == "v2"

    def test_checkpoints_written_to_yaml(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        cp = Checkpoint(
            connector="azure",
            value="cursor-abc",
            updated_at=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        )
        store.set_checkpoint(cp)

        yaml_path = tmp_path / ".mallcop" / "checkpoints.yaml"
        assert yaml_path.exists()

        data = yaml.safe_load(yaml_path.read_text())
        assert "azure" in data
        assert data["azure"]["value"] == "cursor-abc"

    def test_checkpoint_reload_from_disk(self, tmp_path: Path) -> None:
        store1 = JsonlStore(tmp_path)
        cp = Checkpoint(connector="github", value="page-5", updated_at=_utcnow())
        store1.set_checkpoint(cp)

        store2 = JsonlStore(tmp_path)
        result = store2.get_checkpoint("github")
        assert result is not None
        assert result.value == "page-5"

    def test_multiple_connectors(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        cp_az = Checkpoint(connector="azure", value="az-cursor", updated_at=_utcnow())
        cp_gh = Checkpoint(connector="github", value="gh-cursor", updated_at=_utcnow())
        store.set_checkpoint(cp_az)
        store.set_checkpoint(cp_gh)

        assert store.get_checkpoint("azure").value == "az-cursor"
        assert store.get_checkpoint("github").value == "gh-cursor"


class TestJsonlStoreBaseline:
    def test_get_baseline_empty(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        bl = store.get_baseline()
        assert bl.frequency_tables == {}
        assert bl.known_entities == {}
        assert bl.relationships == {}

    def test_update_and_get_baseline(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        events = [_make_event(id="evt_bl", actor="admin@ex.com", source="azure")]
        store.append_events(events)
        store.update_baseline(events)
        bl = store.get_baseline()
        # update_baseline should populate some baseline data
        assert isinstance(bl, Baseline)

    def test_update_baseline_with_window_excludes_old_freq(self, tmp_path: Path) -> None:
        """With window_days, old events are excluded from frequency tables."""
        store = JsonlStore(tmp_path)
        now = _utcnow()
        old_event = _make_event(
            id="evt_old", actor="old@ex.com", source="azure",
            timestamp=now - timedelta(days=45),
        )
        new_event = _make_event(
            id="evt_new", actor="new@ex.com", source="azure",
            timestamp=now - timedelta(days=5),
        )
        events = [old_event, new_event]
        store.append_events(events)
        store.update_baseline(events, window_days=30)
        bl = store.get_baseline()

        # Frequency tables should only count new event
        assert "azure:role_assignment:new@ex.com" in bl.frequency_tables
        assert "azure:role_assignment:old@ex.com" not in bl.frequency_tables

    def test_update_baseline_with_window_keeps_all_known_entities(self, tmp_path: Path) -> None:
        """With window_days, known entities still include all-time actors."""
        store = JsonlStore(tmp_path)
        now = _utcnow()
        old_event = _make_event(
            id="evt_old", actor="old@ex.com", source="azure",
            timestamp=now - timedelta(days=45),
        )
        new_event = _make_event(
            id="evt_new", actor="new@ex.com", source="azure",
            timestamp=now - timedelta(days=5),
        )
        events = [old_event, new_event]
        store.append_events(events)
        store.update_baseline(events, window_days=30)
        bl = store.get_baseline()

        # Known entities should include BOTH actors
        assert "old@ex.com" in bl.known_entities.get("actors", [])
        assert "new@ex.com" in bl.known_entities.get("actors", [])

    def test_update_baseline_populates_actor_roles(self, tmp_path: Path) -> None:
        """update_baseline should extract actor_roles from elevation event types."""
        store = JsonlStore(tmp_path)
        events = [
            _make_event(
                id="evt_role1",
                actor="admin@ex.com",
                source="azure",
                event_type="role_assignment",
                metadata={"role_name": "Owner"},
            ),
            _make_event(
                id="evt_role2",
                actor="admin@ex.com",
                source="azure",
                event_type="permission_change",
                metadata={"permission_level": "write"},
            ),
            _make_event(
                id="evt_role3",
                actor="dev@ex.com",
                source="github",
                event_type="collaborator_added",
                metadata={"permission_level": "admin"},
            ),
            # Non-elevation event type should NOT populate actor_roles
            _make_event(
                id="evt_normal",
                actor="user@ex.com",
                source="azure",
                event_type="sign_in",
                metadata={"role_name": "viewer"},
            ),
        ]
        store.append_events(events)
        store.update_baseline(events)
        bl = store.get_baseline()

        actor_roles = bl.known_entities.get("actor_roles", {})
        assert "admin@ex.com" in actor_roles
        assert "Owner" in actor_roles["admin@ex.com"]
        assert "write" in actor_roles["admin@ex.com"]
        assert "dev@ex.com" in actor_roles
        assert "admin" in actor_roles["dev@ex.com"]
        # Non-elevation event type should not add roles
        assert "user@ex.com" not in actor_roles

    def test_update_baseline_actor_roles_admin_action_uses_event_type(self, tmp_path: Path) -> None:
        """admin_action events with no role_name/permission_level use event_type as role key."""
        store = JsonlStore(tmp_path)
        events = [
            _make_event(
                id="evt_admin",
                actor="admin@ex.com",
                source="m365",
                event_type="admin_action",
                metadata={},
            ),
        ]
        store.append_events(events)
        store.update_baseline(events)
        bl = store.get_baseline()

        actor_roles = bl.known_entities.get("actor_roles", {})
        assert "admin@ex.com" in actor_roles
        assert "admin_action" in actor_roles["admin@ex.com"]

    def test_update_baseline_actor_roles_persists_across_updates(self, tmp_path: Path) -> None:
        """actor_roles accumulate across multiple update_baseline calls."""
        store = JsonlStore(tmp_path)
        events1 = [
            _make_event(
                id="evt_1",
                actor="admin@ex.com",
                source="azure",
                event_type="role_assignment",
                metadata={"role_name": "Owner"},
            ),
        ]
        store.append_events(events1)
        store.update_baseline(events1)

        events2 = [
            _make_event(
                id="evt_2",
                actor="admin@ex.com",
                source="azure",
                event_type="role_assignment",
                metadata={"role_name": "Contributor"},
            ),
        ]
        store.append_events(events2)
        store.update_baseline(events2)
        bl = store.get_baseline()

        actor_roles = bl.known_entities.get("actor_roles", {})
        assert "admin@ex.com" in actor_roles
        assert "Owner" in actor_roles["admin@ex.com"]
        assert "Contributor" in actor_roles["admin@ex.com"]

    def test_update_baseline_without_window_includes_all_freq(self, tmp_path: Path) -> None:
        """Without window_days, all events are counted in frequency tables."""
        store = JsonlStore(tmp_path)
        now = _utcnow()
        old_event = _make_event(
            id="evt_old", actor="old@ex.com", source="azure",
            timestamp=now - timedelta(days=45),
        )
        new_event = _make_event(
            id="evt_new", actor="new@ex.com", source="azure",
            timestamp=now - timedelta(days=5),
        )
        events = [old_event, new_event]
        store.append_events(events)
        store.update_baseline(events)
        bl = store.get_baseline()

        # Both events should be in frequency tables
        assert "azure:role_assignment:old@ex.com" in bl.frequency_tables
        assert "azure:role_assignment:new@ex.com" in bl.frequency_tables


class TestBaselineRelationships:
    """Relationships must be recomputed from all passed events each call."""

    def test_relationships_from_all_events(self, tmp_path: Path) -> None:
        """When all events are passed, relationships reflect full history."""
        store = JsonlStore(tmp_path)
        events = [
            _make_event(id="evt_1", actor="alice@ex.com", target="/repo/A"),
            _make_event(id="evt_2", actor="bob@ex.com", target="/repo/B"),
        ]
        store.append_events(events)
        store.update_baseline(events)

        bl = store.get_baseline()
        assert "alice@ex.com:/repo/A" in bl.relationships
        assert "bob@ex.com:/repo/B" in bl.relationships
        assert bl.relationships["alice@ex.com:/repo/A"]["count"] == 1

    def test_relationships_count_multiple_events(self, tmp_path: Path) -> None:
        """Multiple events for same actor:target should sum counts."""
        store = JsonlStore(tmp_path)
        events = [
            _make_event(id="evt_1", actor="alice@ex.com", target="/repo/A"),
            _make_event(id="evt_2", actor="alice@ex.com", target="/repo/A"),
        ]
        store.append_events(events)
        store.update_baseline(events)

        bl = store.get_baseline()
        assert bl.relationships["alice@ex.com:/repo/A"]["count"] == 2

    def test_subset_events_lose_history(self, tmp_path: Path) -> None:
        """Passing a subset of events recomputes only from that subset.

        This documents the design: callers must pass ALL events to preserve
        relationship history. The ack command was fixed to do this.
        """
        store = JsonlStore(tmp_path)
        all_events = [
            _make_event(id="evt_1", actor="alice@ex.com", target="/repo/A"),
            _make_event(id="evt_2", actor="bob@ex.com", target="/repo/B"),
        ]
        store.append_events(all_events)
        store.update_baseline(all_events)

        # Passing only a subset wipes relationships not in that subset
        store.update_baseline([all_events[1]])
        bl = store.get_baseline()
        assert "bob@ex.com:/repo/B" in bl.relationships
        assert "alice@ex.com:/repo/A" not in bl.relationships


class TestPathTraversal:
    """Path traversal guard in _event_file_path."""

    def test_traversal_source_raises(self, tmp_path: Path) -> None:
        """A source containing ../ must raise ValueError."""
        store = JsonlStore(tmp_path)
        event = _make_event(source="../etc/passwd")
        with pytest.raises(ValueError, match="Invalid source name"):
            store.append_events([event])

    def test_traversal_source_backslash_raises(self, tmp_path: Path) -> None:
        """A source with backslash traversal must raise ValueError."""
        store = JsonlStore(tmp_path)
        event = _make_event(source="..\\etc\\passwd")
        with pytest.raises(ValueError, match="Invalid source name"):
            store.append_events([event])

    def test_url_encoded_traversal_raises(self, tmp_path: Path) -> None:
        """URL-encoded path separators must be rejected."""
        store = JsonlStore(tmp_path)
        event = _make_event(source="azure%2F..%2F..%2F")
        with pytest.raises(ValueError, match="Invalid source name"):
            store.append_events([event])

    def test_unicode_separator_raises(self, tmp_path: Path) -> None:
        """Unicode path-like characters must be rejected."""
        store = JsonlStore(tmp_path)
        event = _make_event(source="azure\u2044dotdot")
        with pytest.raises(ValueError, match="Invalid source name"):
            store.append_events([event])

    def test_empty_source_raises(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        event = _make_event(source="")
        with pytest.raises(ValueError, match="Invalid source name"):
            store.append_events([event])

    def test_source_with_spaces_raises(self, tmp_path: Path) -> None:
        store = JsonlStore(tmp_path)
        event = _make_event(source="my source")
        with pytest.raises(ValueError, match="Invalid source name"):
            store.append_events([event])

    def test_normal_source_works(self, tmp_path: Path) -> None:
        """A normal source name works without error."""
        store = JsonlStore(tmp_path)
        event = _make_event(source="azure")
        store.append_events([event])
        events = store.query_events(source="azure")
        assert len(events) == 1
        assert events[0].source == "azure"

    def test_source_with_hyphens_dots_works(self, tmp_path: Path) -> None:
        """Sources like container-logs and m365.audit should work."""
        store = JsonlStore(tmp_path)
        for source in ["container-logs", "m365.audit", "azure_activity"]:
            event = _make_event(source=source)
            store.append_events([event])


class TestAtomicWrites:
    """Verify that store writes use atomic temp-file-then-replace pattern."""

    def test_rewrite_findings_atomic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_rewrite_findings uses os.replace, not direct open('w')."""
        import os as _os

        store = JsonlStore(tmp_path)
        store.append_findings([_make_finding()])

        replaced = []
        original_replace = _os.replace

        def mock_replace(src, dst):
            replaced.append((src, str(dst)))
            return original_replace(src, dst)

        monkeypatch.setattr("os.replace", mock_replace)
        store._rewrite_findings()

        assert len(replaced) == 1
        assert replaced[0][1] == str(store._findings_path)

    def test_write_checkpoints_atomic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_write_checkpoints uses os.replace."""
        import os as _os

        store = JsonlStore(tmp_path)
        cp = Checkpoint(connector="test", value="v1", updated_at=_utcnow())
        store.set_checkpoint(cp)

        replaced = []
        original_replace = _os.replace

        def mock_replace(src, dst):
            replaced.append((src, str(dst)))
            return original_replace(src, dst)

        monkeypatch.setattr("os.replace", mock_replace)
        store._write_checkpoints()

        assert len(replaced) == 1
        assert replaced[0][1] == str(store._checkpoints_path)

    def test_update_baseline_atomic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """update_baseline uses os.replace."""
        import os as _os

        store = JsonlStore(tmp_path)

        replaced = []
        original_replace = _os.replace

        def mock_replace(src, dst):
            replaced.append((src, str(dst)))
            return original_replace(src, dst)

        monkeypatch.setattr("os.replace", mock_replace)
        store.update_baseline([_make_event()])

        assert len(replaced) == 1
        assert replaced[0][1] == str(store._baseline_path)

    def test_rewrite_findings_cleans_up_on_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """If writing fails, temp file is cleaned up."""
        store = JsonlStore(tmp_path)
        store.append_findings([_make_finding()])

        def boom(src, dst):
            raise IOError("disk full")

        monkeypatch.setattr("os.replace", boom)

        with pytest.raises(IOError, match="disk full"):
            store._rewrite_findings()

        # No temp files left behind
        temps = list(tmp_path.glob("*.tmp"))
        assert temps == []
