"""Tests for baseline computation: hour_bucket, learning mode."""

from datetime import datetime, timedelta, timezone

import pytest

from mallcop.baseline import (
    hour_bucket,
    is_learning_mode,
)
from mallcop.schemas import Event, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    timestamp: datetime | None = None,
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
    action: str = "create",
    target: str = "/subscriptions/123/roleAssignments/456",
    metadata: dict | None = None,
    **overrides,
) -> Event:
    defaults = dict(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.WARN,
        metadata=metadata or {},
        raw={},
    )
    defaults.update(overrides)
    return Event(**defaults)


# --- Hour bucket ---


class TestHourBucket:
    def test_hour_0_maps_to_0(self) -> None:
        assert hour_bucket(0) == 0

    def test_hour_3_maps_to_0(self) -> None:
        assert hour_bucket(3) == 0

    def test_hour_4_maps_to_4(self) -> None:
        assert hour_bucket(4) == 4

    def test_hour_7_maps_to_4(self) -> None:
        assert hour_bucket(7) == 4

    def test_hour_23_maps_to_20(self) -> None:
        assert hour_bucket(23) == 20

    def test_hour_12_maps_to_12(self) -> None:
        assert hour_bucket(12) == 12

    def test_all_six_buckets(self) -> None:
        """There are exactly 6 buckets: 0, 4, 8, 12, 16, 20."""
        buckets = {hour_bucket(h) for h in range(24)}
        assert buckets == {0, 4, 8, 12, 16, 20}


# --- Learning mode ---


class TestIsLearningMode:
    def test_no_events_is_learning(self) -> None:
        """A connector with no events is in learning mode."""
        assert is_learning_mode("azure", []) is True

    def test_within_14_days_is_learning(self) -> None:
        """A connector with first event <14 days ago is in learning mode."""
        now = _utcnow()
        first_event_ts = now - timedelta(days=10)
        events = [_make_event(timestamp=first_event_ts, source="azure")]
        assert is_learning_mode("azure", events) is True

    def test_after_14_days_is_not_learning(self) -> None:
        """A connector with first event >=14 days ago is NOT in learning mode."""
        now = _utcnow()
        first_event_ts = now - timedelta(days=15)
        events = [_make_event(timestamp=first_event_ts, source="azure")]
        assert is_learning_mode("azure", events) is False

    def test_exactly_14_days_is_not_learning(self) -> None:
        """At exactly 14 days, learning mode is over."""
        now = _utcnow()
        first_event_ts = now - timedelta(days=14)
        events = [_make_event(timestamp=first_event_ts, source="azure")]
        assert is_learning_mode("azure", events) is False

    def test_per_connector_learning(self) -> None:
        """Learning mode is per-connector. Old connector live, new connector learning."""
        now = _utcnow()
        old_event = _make_event(id="evt_old", timestamp=now - timedelta(days=30), source="azure")
        new_event = _make_event(id="evt_new", timestamp=now - timedelta(days=5), source="github")
        all_events = [old_event, new_event]

        # azure has events >14 days old -> not learning
        azure_events = [e for e in all_events if e.source == "azure"]
        assert is_learning_mode("azure", azure_events) is False

        # github has events <14 days old -> learning
        github_events = [e for e in all_events if e.source == "github"]
        assert is_learning_mode("github", github_events) is True

    def test_only_considers_matching_connector(self) -> None:
        """Events from other connectors are ignored."""
        now = _utcnow()
        events = [_make_event(timestamp=now - timedelta(days=30), source="azure")]
        # Asking about github with no github events -> learning
        github_events = [e for e in events if e.source == "github"]
        assert is_learning_mode("github", github_events) is True

    def test_learning_mode_uses_earliest_event(self) -> None:
        """Learning mode checks the earliest event, not the latest."""
        now = _utcnow()
        events = [
            _make_event(id="evt_1", timestamp=now - timedelta(days=20), source="azure"),
            _make_event(id="evt_2", timestamp=now - timedelta(days=1), source="azure"),
        ]
        # First event is 20 days ago -> not learning
        assert is_learning_mode("azure", events) is False


# --- Relationship enrichment ---


class TestRelationshipEnrichment:
    """Relationships: keyed by 'actor:target', value has count/first_seen/last_seen."""

    def _store_with_events(self, events: list[Event]) -> "JsonlStore":
        import tempfile
        from pathlib import Path
        from mallcop.store import JsonlStore

        tmp = Path(tempfile.mkdtemp())
        store = JsonlStore(tmp)
        for evt in events:
            store.append_events([evt])
        store.update_baseline(events)
        return store

    def test_single_event_creates_relationship(self) -> None:
        """One event produces one relationship entry with count=1."""
        ts = _utcnow()
        evt = _make_event(actor="alice@co.com", target="/res/1", timestamp=ts)
        store = self._store_with_events([evt])
        bl = store.get_baseline()
        key = "alice@co.com:/res/1"
        assert key in bl.relationships
        rel = bl.relationships[key]
        assert rel["count"] == 1
        assert rel["first_seen"] == ts.isoformat()
        assert rel["last_seen"] == ts.isoformat()

    def test_multiple_events_same_pair_aggregates(self) -> None:
        """Repeated actor+target increments count and updates last_seen."""
        t1 = _utcnow() - timedelta(hours=5)
        t2 = _utcnow() - timedelta(hours=1)
        events = [
            _make_event(id="e1", actor="bob@co.com", target="/res/A", timestamp=t1),
            _make_event(id="e2", actor="bob@co.com", target="/res/A", timestamp=t2),
        ]
        store = self._store_with_events(events)
        rel = store.get_baseline().relationships["bob@co.com:/res/A"]
        assert rel["count"] == 2
        assert rel["first_seen"] == t1.isoformat()
        assert rel["last_seen"] == t2.isoformat()

    def test_different_targets_separate_keys(self) -> None:
        """Same actor accessing different targets creates separate entries."""
        events = [
            _make_event(id="e1", actor="carol@co.com", target="/res/X"),
            _make_event(id="e2", actor="carol@co.com", target="/res/Y"),
        ]
        store = self._store_with_events(events)
        rels = store.get_baseline().relationships
        assert "carol@co.com:/res/X" in rels
        assert "carol@co.com:/res/Y" in rels

    def test_incremental_update_preserves_existing(self) -> None:
        """Calling update_baseline again merges, keeping first_seen from prior run."""
        import tempfile
        from pathlib import Path
        from mallcop.store import JsonlStore

        t1 = _utcnow() - timedelta(hours=10)
        t2 = _utcnow() - timedelta(hours=1)

        tmp = Path(tempfile.mkdtemp())
        store = JsonlStore(tmp)
        evt1 = _make_event(id="e1", actor="dan@co.com", target="/res/Z", timestamp=t1)
        store.append_events([evt1])
        store.update_baseline([evt1])

        # Second update with both events (update_baseline receives ALL events)
        evt2 = _make_event(id="e2", actor="dan@co.com", target="/res/Z", timestamp=t2)
        store.append_events([evt2])
        store.update_baseline([evt1, evt2])

        rel = store.get_baseline().relationships["dan@co.com:/res/Z"]
        assert rel["count"] == 2
        assert rel["first_seen"] == t1.isoformat()
        assert rel["last_seen"] == t2.isoformat()

    def test_relationships_round_trip_via_dict(self) -> None:
        """Relationships survive Baseline.to_dict / from_dict."""
        from mallcop.schemas import Baseline

        rels = {
            "alice@co.com:/res/1": {
                "count": 3,
                "first_seen": "2026-01-01T00:00:00+00:00",
                "last_seen": "2026-03-01T00:00:00+00:00",
            }
        }
        bl = Baseline(frequency_tables={}, known_entities={}, relationships=rels)
        restored = Baseline.from_dict(bl.to_dict())
        assert restored.relationships == rels


# ---------------------------------------------------------------------------
# update_actor_context type merge (2.31)
# ---------------------------------------------------------------------------


class TestActorContextTypeMerge:
    """Verify that actor type is merged with correct precedence.

    Non-human types (automation/service) should not be downgraded to human
    by subsequent observations. Human type should not override an existing
    automation/service classification.
    """

    def _make_record(self, finding_id: str, reason: str, actor_name: str):
        from mallcop.feedback import FeedbackRecord, HumanAction

        event = _make_event(
            id=f"evt_{finding_id}",
            actor=actor_name,
        )
        return FeedbackRecord(
            finding_id=finding_id,
            human_action=HumanAction.AGREE,
            reason=reason,
            original_action="escalate",
            original_reason=None,
            timestamp=_utcnow(),
            events=[event.to_dict()],
            baseline_snapshot={"actor": actor_name},
            annotations=[],
        )

    def test_automation_preserved_when_new_observation_is_human(self):
        """Existing automation type must NOT be downgraded to human."""
        from mallcop.baseline import update_actor_context
        from mallcop.schemas import ActorProfile, Baseline

        existing_profile = ActorProfile(
            location=None, timezone=None, type="automation",
            last_confirmed=_utcnow(), source_feedback_ids=["fnd_001"],
            confidence=1.0,
        )
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"deploy-bot": existing_profile},
        )

        record = self._make_record("fnd_002", "this is a human user", "deploy-bot")
        updated = update_actor_context(baseline, [record])
        # Human observation must not downgrade the existing automation label.
        assert updated.actor_context["deploy-bot"].type == "automation"

    def test_human_overridden_by_automation(self):
        """If existing type is human and new observation is automation, prefer automation."""
        from mallcop.baseline import update_actor_context
        from mallcop.schemas import ActorProfile, Baseline

        existing_profile = ActorProfile(
            location=None, timezone=None, type="human",
            last_confirmed=_utcnow(), source_feedback_ids=["fnd_001"],
            confidence=1.0,
        )
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"ci-runner": existing_profile},
        )

        record = self._make_record("fnd_003", "this is automation", "ci-runner")
        updated = update_actor_context(baseline, [record])
        # Automation is more specific; it should win over human.
        assert updated.actor_context["ci-runner"].type == "automation"

    def test_human_stays_human_when_existing_is_also_human(self):
        """human + human → human (no conflict, type stays human)."""
        from mallcop.baseline import update_actor_context
        from mallcop.schemas import ActorProfile, Baseline

        existing_profile = ActorProfile(
            location=None, timezone=None, type="human",
            last_confirmed=_utcnow(), source_feedback_ids=["fnd_001"],
            confidence=1.0,
        )
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"alice@corp.com": existing_profile},
        )

        record = self._make_record("fnd_004", "this is a human user", "alice@corp.com")
        updated = update_actor_context(baseline, [record])
        assert updated.actor_context["alice@corp.com"].type == "human"
