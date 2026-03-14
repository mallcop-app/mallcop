"""Full-loop integration test: feedback → learned context → enriched investigation.

Validates the learning flywheel spec end-to-end (without live LLM):
1. Actor triggers unusual-timing finding
2. Human overrides (says it's London travel)
3. update_actor_context extracts London/timezone from feedback reason
4. check-baseline tool response includes actor_context with London profile
5. Enriched baseline context is richer than un-enriched baseline

Bead: mallcop-9hf5.15
"""
from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy

import pytest

from mallcop.baseline import update_actor_context
from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.schemas import ActorProfile, Baseline, Event, Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(actor: str = "admin-user", event_type: str = "login") -> Event:
    now = datetime.now(timezone.utc)
    return Event(
        id="evt_travel_001",
        timestamp=now,
        ingested_at=now,
        source="azure",
        event_type=event_type,
        actor=actor,
        action="login",
        target="acme-corp/tenant",
        severity=Severity.INFO,
        metadata={"location": "London, UK", "ip": "198.51.100.50"},
        raw={},
    )


def _make_finding(actor: str = "admin-user") -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        id="fnd_travel_001",
        timestamp=now,
        detector="unusual-timing",
        event_ids=["evt_travel_001"],
        title="Unusual timing: admin-user active at 14:00 UTC",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": actor, "source": "azure"},
    )


def _make_baseline(actor: str = "admin-user", with_context: bool = False) -> Baseline:
    ctx = {}
    if with_context:
        ctx[actor] = ActorProfile(
            location="London",
            timezone="Europe/London",
            type="human",
            last_confirmed=datetime.now(timezone.utc),
            source_feedback_ids=["fnd_travel_001"],
            confidence=1.0,
        )
    return Baseline(
        frequency_tables={"azure:login:admin-user": 340},
        known_entities={"actors": [actor], "sources": ["azure"]},
        relationships={},
        actor_context=ctx,
    )


# ---------------------------------------------------------------------------
# Test 1: Feedback record captures London signal
# ---------------------------------------------------------------------------

class TestFeedbackCapture:
    def test_override_with_london_reason_creates_profile(self):
        """After override with 'London' in reason, actor_context has London profile."""
        baseline = _make_baseline()
        finding = _make_finding()
        event = _make_event()

        record = FeedbackRecord(
            finding_id=finding.id,
            human_action=HumanAction.OVERRIDE,
            reason="admin-user is traveling to London — London working hours shift UTC timing",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime.now(timezone.utc),
            events=[event.to_dict()],
            baseline_snapshot={"actors": ["admin-user"]},
            annotations=[],
            detector="unusual-timing",
            source="individual",
            weight=1.0,
        )

        updated = update_actor_context(baseline, [record])

        assert "admin-user" in updated.actor_context
        profile = updated.actor_context["admin-user"]
        assert profile.location == "London"
        assert profile.confidence == pytest.approx(1.0, abs=0.01)

    def test_override_with_timezone_reason_extracts_timezone(self):
        """Reason mentioning 'Europe/London' updates actor timezone."""
        baseline = _make_baseline()
        event = _make_event()

        record = FeedbackRecord(
            finding_id="fnd_001",
            human_action=HumanAction.OVERRIDE,
            reason="admin-user is in Europe/London timezone on business trip",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime.now(timezone.utc),
            events=[event.to_dict()],
            baseline_snapshot={},
            annotations=[],
            detector="unusual-timing",
            source="individual",
            weight=1.0,
        )

        updated = update_actor_context(baseline, [record])

        assert "admin-user" in updated.actor_context
        profile = updated.actor_context["admin-user"]
        assert profile.timezone == "Europe/London"


# ---------------------------------------------------------------------------
# Test 2: check-baseline reflects learned actor context
# ---------------------------------------------------------------------------

class TestCheckBaselineEnrichment:
    def test_enriched_baseline_exposes_actor_context_in_tool(self):
        """check-baseline returns actor_context when actor has a learned profile."""
        from mallcop.tools.baseline import check_baseline
        from mallcop.tools import ToolContext
        from tests.shakedown.scenario_store import ScenarioStore

        baseline_enriched = _make_baseline(with_context=True)
        store = ScenarioStore(
            events=[_make_event()],
            baseline=baseline_enriched,
            findings=[_make_finding()],
        )

        ctx = ToolContext(store=store, connectors={}, config=None)
        result = check_baseline(ctx, actor="admin-user")

        assert "actor_context" in result
        profile = result["actor_context"]
        assert profile["location"] == "London"
        assert profile["timezone"] == "Europe/London"

    def test_bare_baseline_lacks_actor_context(self):
        """check-baseline returns no actor_context when actor has no learned profile."""
        from mallcop.tools.baseline import check_baseline
        from mallcop.tools import ToolContext
        from tests.shakedown.scenario_store import ScenarioStore

        baseline_bare = _make_baseline(with_context=False)
        store = ScenarioStore(
            events=[_make_event()],
            baseline=baseline_bare,
            findings=[_make_finding()],
        )

        ctx = ToolContext(store=store, connectors={}, config=None)
        result = check_baseline(ctx, actor="admin-user")

        assert "actor_context" not in result

    def test_feedback_then_enriched_check_baseline(self):
        """After applying feedback, check-baseline shows the learned profile."""
        from mallcop.tools.baseline import check_baseline
        from mallcop.tools import ToolContext
        from tests.shakedown.scenario_store import ScenarioStore

        # Step 1: baseline with no actor context
        baseline = _make_baseline(with_context=False)
        event = _make_event()
        finding = _make_finding()

        # Step 2: human provides override with London location
        record = FeedbackRecord(
            finding_id=finding.id,
            human_action=HumanAction.OVERRIDE,
            reason="admin-user is working from London this week — business travel",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime.now(timezone.utc),
            events=[event.to_dict()],
            baseline_snapshot={"actors": ["admin-user"]},
            annotations=[],
            detector="unusual-timing",
            source="individual",
            weight=1.0,
        )

        # Step 3: apply feedback to baseline
        enriched_baseline = update_actor_context(baseline, [record])
        assert "admin-user" in enriched_baseline.actor_context

        # Step 4: check-baseline with enriched baseline shows learned profile
        store = ScenarioStore(
            events=[event],
            baseline=enriched_baseline,
            findings=[finding],
        )
        ctx = ToolContext(store=store, connectors={}, config=None)
        result = check_baseline(ctx, actor="admin-user")

        assert "actor_context" in result
        profile_dict = result["actor_context"]
        assert profile_dict["location"] == "London"


# ---------------------------------------------------------------------------
# Test 3: Enriched baseline vs bare baseline richness
# ---------------------------------------------------------------------------

class TestEnrichmentRichness:
    def test_enriched_profile_has_location_and_timezone(self):
        """Enriched actor profile provides both location and timezone signals."""
        profile = ActorProfile(
            location="London",
            timezone="Europe/London",
            type="human",
            last_confirmed=datetime.now(timezone.utc),
            source_feedback_ids=["fnd_travel_001"],
            confidence=1.0,
        )
        d = profile.to_dict()
        assert d["location"] == "London"
        assert d["timezone"] == "Europe/London"
        assert d["confidence"] == 1.0

    def test_batch_feedback_profile_lower_confidence(self):
        """Profile built from batch feedback has lower confidence than individual."""
        baseline = _make_baseline()
        event = _make_event()

        batch_record = FeedbackRecord(
            finding_id="fnd_b",
            human_action=HumanAction.OVERRIDE,
            reason="London employee",
            original_action="escalate",
            original_reason=None,
            timestamp=datetime.now(timezone.utc),
            events=[event.to_dict()],
            baseline_snapshot={},
            annotations=[],
            detector="unusual-timing",
            source="batch",
            weight=0.3,
        )

        updated = update_actor_context(baseline, [batch_record])
        profile = updated.actor_context.get("admin-user")
        assert profile is not None
        assert profile.confidence < 1.0
        assert profile.confidence == pytest.approx(0.3, abs=0.05)
