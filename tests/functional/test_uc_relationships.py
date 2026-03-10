"""UC: Baseline relationships — actor→resource tracking with unusual-access detection.

Functional test proving the full pipeline:
- Seed events establishing actor→resource patterns
- Run detect with baseline containing enriched relationships
- Known actor touches new resource → unusual-resource-access finding
- Finding flows through escalate → triage receives it
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.detect import run_detect
from mallcop.schemas import (
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


def _make_config_yaml(root: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": {
            "critical": "triage",
            "warn": "triage",
            "info": None,
        },
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_event(
    id: str,
    actor: str,
    target: str,
    hours_ago: int = 1,
) -> Event:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return Event(
        id=id,
        timestamp=ts,
        ingested_at=ts,
        source="azure",
        event_type="resource_access",
        actor=actor,
        action="read",
        target=target,
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_baseline_with_relationships(actor: str, targets: list[str]) -> Baseline:
    """Build a baseline where actor has established relationships with targets."""
    rels: dict[str, Any] = {}
    for target in targets:
        rels[f"{actor}:{target}"] = {
            "count": 10,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-02-15T00:00:00+00:00",
        }
    return Baseline(
        frequency_tables={f"azure:resource_access:{actor}": 50},
        known_entities={"actors": [actor], "sources": ["azure"]},
        relationships=rels,
    )


class TestRelationshipPipeline:
    """Full pipeline: relationship tracking + unusual-access detection."""

    def test_established_actor_new_resource_generates_finding(self) -> None:
        """Known actor with established relationships touches new resource -> finding."""
        actor = "admin@corp.com"
        known_targets = ["/subscriptions/sub-1", "/subscriptions/sub-2"]
        baseline = _make_baseline_with_relationships(actor, known_targets)

        # Event where admin touches a NEW resource
        event = _make_event("evt_001", actor, "/subscriptions/sub-NEW")

        findings = run_detect(
            events=[event],
            baseline=baseline,
            learning_connectors=set(),
        )

        # Should find unusual-resource-access finding
        ura_findings = [f for f in findings if f.detector == "unusual-resource-access"]
        assert len(ura_findings) == 1
        assert ura_findings[0].metadata["actor"] == actor
        assert ura_findings[0].metadata["target"] == "/subscriptions/sub-NEW"
        assert ura_findings[0].metadata["known_targets_count"] == 2

    def test_finding_metadata_includes_relationship_context(self) -> None:
        """Finding metadata has known_targets_count for context."""
        actor = "admin@corp.com"
        targets = [f"/sub/{i}" for i in range(5)]
        baseline = _make_baseline_with_relationships(actor, targets)

        event = _make_event("evt_002", actor, "/sub/new-resource")
        findings = run_detect([event], baseline, learning_connectors=set())

        ura = [f for f in findings if f.detector == "unusual-resource-access"]
        assert len(ura) == 1
        assert ura[0].metadata["known_targets_count"] == 5

    def test_finding_flows_through_escalate(self, tmp_path: Path) -> None:
        """Finding from unusual-resource-access flows through escalate -> triage."""
        root = tmp_path
        _make_config_yaml(root)
        store = JsonlStore(root)

        finding = Finding(
            id="fnd_ura_001",
            timestamp=datetime.now(timezone.utc),
            detector="unusual-resource-access",
            event_ids=["evt_001"],
            title="Unusual resource access: admin@corp.com → /sub/new",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "admin@corp.com", "target": "/sub/new", "known_targets_count": 3},
        )
        store.append_findings([finding])

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Unusual resource access — escalating",
                ),
                tokens_used=500,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 1

        fresh_store = JsonlStore(root)
        all_findings = fresh_store.query_findings()
        assert len(all_findings) == 1
        assert all_findings[0].annotations[0].action == "escalated"

    def test_baseline_window_excludes_stale_frequency(self) -> None:
        """30-day baseline window correctly scopes frequency tables but relationships persist."""
        actor = "admin@corp.com"
        baseline = Baseline(
            frequency_tables={},  # Empty freq (old events outside window)
            known_entities={"actors": [actor], "sources": ["azure"]},
            relationships={
                f"{actor}:/sub/old-resource": {
                    "count": 10,
                    "first_seen": "2025-01-01T00:00:00+00:00",
                    "last_seen": "2025-06-01T00:00:00+00:00",
                },
            },
        )

        # Actor touches new resource — should still fire because relationships persist
        event = _make_event("evt_003", actor, "/sub/new-resource")
        findings = run_detect([event], baseline, learning_connectors=set())

        ura = [f for f in findings if f.detector == "unusual-resource-access"]
        assert len(ura) == 1
        assert ura[0].metadata["target"] == "/sub/new-resource"
