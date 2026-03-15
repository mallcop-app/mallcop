"""UC-3: GitHub permission change detected.

A new collaborator is added to a repo. The GitHub connector picks it up on
next poll. Two detectors fire:
  - new-actor (never-seen user)
  - new-external-access (non-org member added as collaborator)

Triage investigates: checks if this matches any known onboarding pattern.
If not, escalates to Teams.

We mock:
  - GitHub connector (recorded fixture — no live API calls)
  - LLM client (deterministic triage decisions)

We verify:
  - GitHub connector produces collaborator_added event from audit log fixture
  - new-actor detector fires for never-seen actor
  - new-external-access detector fires for non-org collaborator_added
  - Triage actor produces escalation resolution
  - Full pipeline (scan -> detect -> escalate -> review) works end-to-end
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.cli import cli
from mallcop.connectors.github.connector import GitHubConnector
from mallcop.schemas import (
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "github"


def _make_config_yaml(root: Path) -> None:
    """Write mallcop.yaml configured for GitHub monitoring."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"github": {"org": "acme-corp"}},
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
        "squelch": 0,  # disabled: functional tests are not testing squelch gating
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _load_fixture(name: str) -> list[dict[str, Any]]:
    """Load a GitHub audit log fixture file."""
    path = FIXTURE_DIR / name
    with open(path) as f:
        return json.load(f)


def _seed_known_github_actors(root: Path) -> tuple[list[Event], datetime]:
    """Seed baseline with known GitHub actors (admin-user, devops-bot).

    Returns (known_events, now).
    """
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=20)

    known_actors = ["admin-user", "devops-bot"]
    known_events: list[Event] = []
    for i, actor in enumerate(known_actors):
        for j in range(5):
            ts = base_time + timedelta(hours=i * 6 + j)
            known_events.append(Event(
                id=f"evt_gh_known_{actor}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source="github",
                event_type="push",
                actor=actor,
                action="git.push",
                target=f"acme-corp/repo-{i}",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ))

    store = JsonlStore(root)
    store.append_events(known_events)
    store.update_baseline(known_events)

    return known_events, now


def _connector_events_from_fixture(fixture_name: str) -> list[Event]:
    """Run the GitHub connector's event parsing against a fixture file.

    Uses the connector's poll logic by feeding raw entries through
    the same classification/mapping that poll() uses.
    """
    from mallcop.connectors.github.connector import (
        _classify_action,
        _map_severity,
        _ts_from_epoch_ms,
    )
    from mallcop.connectors._util import make_event_id as _make_event_id

    raw_entries = _load_fixture(fixture_name)
    now = datetime.now(timezone.utc)
    events: list[Event] = []

    for entry in raw_entries:
        action = entry.get("action", "")
        event_type = _classify_action(action)
        severity = _map_severity(event_type)
        ts_ms = entry.get("@timestamp") or entry.get("created_at", 0)
        timestamp = _ts_from_epoch_ms(ts_ms)
        doc_id = entry.get("_document_id", "")

        evt = Event(
            id=_make_event_id(doc_id),
            timestamp=timestamp,
            ingested_at=now,
            source="github",
            event_type=event_type,
            actor=entry.get("actor", "unknown"),
            action=action,
            target=entry.get("repo", entry.get("org", "")),
            severity=severity,
            metadata={"org": "acme-corp", "action_detail": action},
            raw=entry,
        )
        events.append(evt)

    return events


# --- Phase 1: Connector produces events from fixture ---


class TestGitHubConnectorEvents:
    """GitHub connector produces correct events from audit log fixture."""

    def test_connector_parses_collaborator_added(self) -> None:
        """repo.add_member action maps to collaborator_added event type."""
        events = _connector_events_from_fixture("audit_log_new_collaborator.json")

        # Should produce 2 events (1 repo.add_member + 1 git.push)
        assert len(events) == 2

        collab_events = [e for e in events if e.event_type == "collaborator_added"]
        assert len(collab_events) == 1

        evt = collab_events[0]
        assert evt.source == "github"
        assert evt.event_type == "collaborator_added"
        assert evt.actor == "admin-user"
        assert evt.target == "acme-corp/infrastructure"
        assert evt.severity == Severity.WARN
        assert evt.raw["user"] == "external-contractor"

    def test_connector_classifies_push_event(self) -> None:
        """git.push action maps to push event type with INFO severity."""
        events = _connector_events_from_fixture("audit_log_new_collaborator.json")

        push_events = [e for e in events if e.event_type == "push"]
        assert len(push_events) == 1
        assert push_events[0].severity == Severity.INFO


# --- Phase 2: Detectors fire on new collaborator ---


class TestNewActorDetectorOnGitHub:
    """new-actor detector fires for never-seen GitHub user."""

    def test_new_actor_fires_for_unknown_collaborator(self, tmp_path: Path) -> None:
        """New collaborator triggers new-actor finding when not in baseline."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_known_github_actors(root)

        # Inject event for unknown actor (external-contractor) performing
        # an action — simulating the collaborator making their first push
        unknown_events = [
            Event(
                id="evt_gh_external_001",
                timestamp=now - timedelta(hours=1),
                ingested_at=now,
                source="github",
                event_type="push",
                actor="external-contractor",
                action="git.push",
                target="acme-corp/infrastructure",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ),
        ]
        store = JsonlStore(root)
        store.append_events(unknown_events)

        # Run detect
        from mallcop.detect import run_detect

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # new-actor should fire for external-contractor
        new_actor_findings = [
            f for f in findings if f.detector == "new-actor"
        ]
        assert len(new_actor_findings) >= 1

        contractor_findings = [
            f for f in new_actor_findings
            if "external-contractor" in (f.metadata.get("actor", "") or f.title)
        ]
        assert len(contractor_findings) == 1
        assert contractor_findings[0].severity == Severity.WARN


class TestNewExternalAccessDetectorOnGitHub:
    """new-external-access detector fires for non-org member collaborator_added."""

    def test_external_access_fires_for_collaborator_added(self, tmp_path: Path) -> None:
        """collaborator_added without member_type=member triggers external access finding."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_known_github_actors(root)

        # Inject collaborator_added event (no member_type = defaults to external)
        collab_events = [
            Event(
                id="evt_gh_collab_add_001",
                timestamp=now - timedelta(hours=1),
                ingested_at=now,
                source="github",
                event_type="collaborator_added",
                actor="admin-user",
                action="repo.add_member",
                target="acme-corp/infrastructure",
                severity=Severity.WARN,
                metadata={"org": "acme-corp", "action_detail": "repo.add_member"},
                raw={"user": "external-contractor", "action": "repo.add_member"},
            ),
        ]
        store = JsonlStore(root)
        store.append_events(collab_events)

        from mallcop.detect import run_detect

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # new-external-access should fire for collaborator_added
        ext_findings = [
            f for f in findings if f.detector == "new-external-access"
        ]
        assert len(ext_findings) == 1
        assert ext_findings[0].severity == Severity.WARN
        assert "External access granted" in ext_findings[0].title
        assert ext_findings[0].metadata["event_type"] == "collaborator_added"

    def test_internal_member_does_not_trigger(self, tmp_path: Path) -> None:
        """collaborator_added with member_type=member does NOT trigger external access."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_known_github_actors(root)

        # Inject collaborator_added with member_type=member (org member)
        collab_events = [
            Event(
                id="evt_gh_collab_member_001",
                timestamp=now - timedelta(hours=1),
                ingested_at=now,
                source="github",
                event_type="collaborator_added",
                actor="admin-user",
                action="repo.add_member",
                target="acme-corp/infrastructure",
                severity=Severity.WARN,
                metadata={
                    "org": "acme-corp",
                    "action_detail": "repo.add_member",
                    "member_type": "member",
                },
                raw={"user": "new-org-member", "action": "repo.add_member"},
            ),
        ]
        store = JsonlStore(root)
        store.append_events(collab_events)

        from mallcop.detect import run_detect

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # new-external-access should NOT fire for org member
        ext_findings = [
            f for f in findings if f.detector == "new-external-access"
        ]
        assert len(ext_findings) == 0


# --- Phase 3: Both detectors fire together ---


class TestBothDetectorsFire:
    """Both new-actor and new-external-access fire for the same scenario."""

    def test_both_detectors_fire_for_new_external_collaborator(self, tmp_path: Path) -> None:
        """A new external collaborator triggers both detectors simultaneously."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_known_github_actors(root)

        # Inject events: collaborator_added (by admin-user) + push (by new actor)
        # The collaborator_added event itself is acted by admin-user (who adds them)
        # but the new actor "external-contractor" also pushes
        new_events = [
            Event(
                id="evt_gh_collab_add_002",
                timestamp=now - timedelta(hours=2),
                ingested_at=now,
                source="github",
                event_type="collaborator_added",
                actor="admin-user",
                action="repo.add_member",
                target="acme-corp/infrastructure",
                severity=Severity.WARN,
                metadata={"org": "acme-corp", "action_detail": "repo.add_member"},
                raw={"user": "external-contractor", "action": "repo.add_member"},
            ),
            Event(
                id="evt_gh_ext_push_001",
                timestamp=now - timedelta(hours=1),
                ingested_at=now,
                source="github",
                event_type="push",
                actor="external-contractor",
                action="git.push",
                target="acme-corp/infrastructure",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ),
        ]
        store = JsonlStore(root)
        store.append_events(new_events)

        from mallcop.detect import run_detect

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # new-external-access fires on collaborator_added
        ext_findings = [f for f in findings if f.detector == "new-external-access"]
        assert len(ext_findings) == 1

        # new-actor fires for external-contractor (never seen in baseline)
        actor_findings = [f for f in findings if f.detector == "new-actor"]
        contractor_actor_findings = [
            f for f in actor_findings
            if "external-contractor" in (f.metadata.get("actor", "") or f.title)
        ]
        assert len(contractor_actor_findings) == 1

        # Both findings are WARN
        all_relevant = ext_findings + contractor_actor_findings
        assert all(f.severity == Severity.WARN for f in all_relevant)


# --- Phase 4: Triage escalates ---


class TestTriageEscalation:
    """Triage actor investigates and escalates the findings."""

    def test_triage_escalates_new_collaborator_findings(self, tmp_path: Path) -> None:
        """Triage processes findings from both detectors, escalates them."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_known_github_actors(root)

        # Create findings as detect would produce them
        findings = [
            Finding(
                id="fnd_ext_access_001",
                timestamp=now,
                detector="new-external-access",
                event_ids=["evt_gh_collab_add_002"],
                title="External access granted: collaborator_added on github by admin-user",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={
                    "source": "github",
                    "event_type": "collaborator_added",
                    "actor": "admin-user",
                    "target": "acme-corp/infrastructure",
                },
            ),
            Finding(
                id="fnd_new_actor_001",
                timestamp=now,
                detector="new-actor",
                event_ids=["evt_gh_ext_push_001"],
                title="New actor: external-contractor on github",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={"actor": "external-contractor", "sources": ["github"]},
            ),
        ]
        store = JsonlStore(root)
        store.append_findings(findings)

        # Mock triage: escalates both (no known onboarding pattern)
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        f"No known onboarding pattern matches. "
                        f"Escalating for human review: {finding.title}"
                    ),
                ),
                tokens_used=600,
                iterations=2,
            )

        from mallcop.escalate import run_escalate

        result = run_escalate(root, actor_runner=mock_triage)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 2
        assert result["circuit_breaker_triggered"] is False

        # Both findings should have triage annotations
        store2 = JsonlStore(root)
        updated_findings = store2.query_findings()
        for f in updated_findings:
            assert len(f.annotations) >= 1, f"Finding {f.id} should have annotation"
            assert f.annotations[0].actor == "triage"
            assert f.annotations[0].action == "escalated"
            assert "onboarding" in f.annotations[0].content.lower()

    def test_costs_tracked(self, tmp_path: Path) -> None:
        """costs.jsonl records token spend for triage processing."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_known_github_actors(root)

        findings = [
            Finding(
                id="fnd_cost_001",
                timestamp=now,
                detector="new-external-access",
                event_ids=["evt_001"],
                title="External access granted",
                severity=Severity.WARN,
                status=FindingStatus.OPEN,
                annotations=[],
                metadata={"source": "github"},
            ),
        ]
        store = JsonlStore(root)
        store.append_findings(findings)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Escalating",
                ),
                tokens_used=800,
                iterations=1,
            )

        from mallcop.escalate import run_escalate

        run_escalate(root, actor_runner=mock_runner)

        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists()
        cost_data = json.loads(costs_path.read_text().strip().split("\n")[-1])
        assert cost_data["donuts_used"] == 800
        assert cost_data["actors_invoked"] is True


# --- Phase 5: Full end-to-end pipeline ---


class TestFullGitHubPermissionWorkflow:
    """End-to-end: fixture -> connector -> detect -> escalate -> review."""

    def test_full_uc3_pipeline(self, tmp_path: Path) -> None:
        """Full UC-3 pipeline: GitHub audit log -> both detectors -> triage -> review."""
        root = tmp_path
        _make_config_yaml(root)
        runner = CliRunner()

        # Step 1: Seed baseline with known GitHub actors
        _known_events, now = _seed_known_github_actors(root)

        # Step 2: Parse GitHub audit log fixture through connector logic
        connector_events = _connector_events_from_fixture(
            "audit_log_new_collaborator.json"
        )

        # Also add an event from the new external actor (their first push)
        ext_actor_event = Event(
            id="evt_gh_ext_contractor_push",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="github",
            event_type="push",
            actor="external-contractor",
            action="git.push",
            target="acme-corp/infrastructure",
            severity=Severity.INFO,
            metadata={"org": "acme-corp"},
            raw={"raw_data": True},
        )
        all_new_events = connector_events + [ext_actor_event]

        store = JsonlStore(root)
        store.append_events(all_new_events)

        # Step 3: Run detect — should fire both detectors
        from mallcop.detect import run_detect

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # new-external-access fires for collaborator_added
        ext_findings = [f for f in findings if f.detector == "new-external-access"]
        assert len(ext_findings) >= 1, (
            f"Expected new-external-access finding, got detectors: "
            f"{[f.detector for f in findings]}"
        )

        # new-actor fires for external-contractor
        actor_findings = [f for f in findings if f.detector == "new-actor"]
        contractor_findings = [
            f for f in actor_findings
            if "external-contractor" in (f.metadata.get("actor", "") or f.title)
        ]
        assert len(contractor_findings) >= 1, (
            f"Expected new-actor finding for external-contractor, got: "
            f"{[(f.detector, f.title) for f in findings]}"
        )

        store.append_findings(findings)

        # Step 4: Escalate — triage processes findings
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        f"New external collaborator detected. No matching onboarding "
                        f"pattern. Escalating: {finding.title}"
                    ),
                ),
                tokens_used=700,
                iterations=2,
            )

        from mallcop.escalate import run_escalate

        escalate_result = run_escalate(root, actor_runner=mock_triage)
        assert escalate_result["status"] == "ok"
        assert escalate_result["findings_processed"] >= 2

        # Step 5: Review — should show escalated findings
        result = runner.invoke(cli, ["review", "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        review_data = json.loads(result.output)

        assert review_data["status"] == "ok"

        # Collect all findings from review
        all_review_findings = []
        for _sev, flist in review_data["findings_by_severity"].items():
            all_review_findings.extend(flist)

        # Should have both external-access and new-actor findings
        ext_in_review = [
            f for f in all_review_findings
            if f.get("detector") == "new-external-access"
            or "External access" in f.get("title", "")
        ]
        actor_in_review = [
            f for f in all_review_findings
            if f.get("detector") == "new-actor"
            and "external-contractor" in f.get("title", "")
        ]
        assert len(ext_in_review) >= 1, (
            f"Expected new-external-access finding in review, got: "
            f"{[f.get('title') for f in all_review_findings]}"
        )
        assert len(actor_in_review) >= 1, (
            f"Expected new-actor finding for external-contractor in review, got: "
            f"{[f.get('title') for f in all_review_findings]}"
        )

        # All findings should have triage annotations
        for f in ext_in_review + actor_in_review:
            assert len(f["annotations"]) >= 1
            assert f["annotations"][0]["actor"] == "triage"
            assert f["annotations"][0]["action"] == "escalated"

        # POST.md should be loaded
        assert review_data["post_md"] is not None

    def test_full_uc3_with_investigate(self, tmp_path: Path) -> None:
        """After detection + escalation, investigate shows full context."""
        root = tmp_path
        _make_config_yaml(root)
        runner = CliRunner()

        # Setup
        _known_events, now = _seed_known_github_actors(root)

        # Add external actor events
        ext_events = [
            Event(
                id="evt_gh_perm_change_001",
                timestamp=now - timedelta(hours=2),
                ingested_at=now,
                source="github",
                event_type="collaborator_added",
                actor="admin-user",
                action="repo.add_member",
                target="acme-corp/infrastructure",
                severity=Severity.WARN,
                metadata={"org": "acme-corp", "action_detail": "repo.add_member"},
                raw={"user": "external-contractor", "action": "repo.add_member"},
            ),
            Event(
                id="evt_gh_ext_push_002",
                timestamp=now - timedelta(hours=1),
                ingested_at=now,
                source="github",
                event_type="push",
                actor="external-contractor",
                action="git.push",
                target="acme-corp/infrastructure",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ),
        ]
        store = JsonlStore(root)
        store.append_events(ext_events)

        # Create finding directly (simulating detect output)
        finding = Finding(
            id="fnd_uc3_ext_001",
            timestamp=now,
            detector="new-external-access",
            event_ids=["evt_gh_perm_change_001"],
            title="External access granted: collaborator_added on github by admin-user",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={
                "source": "github",
                "event_type": "collaborator_added",
                "actor": "admin-user",
                "target": "acme-corp/infrastructure",
            },
        )
        store.append_findings([finding])

        # Apply triage annotation
        from mallcop.schemas import Annotation

        store.update_finding(
            "fnd_uc3_ext_001",
            annotations=[
                Annotation(
                    actor="triage",
                    timestamp=now,
                    content="External collaborator added to infrastructure repo. Escalating.",
                    action="escalated",
                    reason="No onboarding pattern match",
                )
            ],
        )

        # Investigate the finding
        result = runner.invoke(
            cli, ["investigate", "fnd_uc3_ext_001", "--dir", str(root)]
        )
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        inv_data = json.loads(result.output)

        assert inv_data["status"] == "ok"
        assert inv_data["finding"]["id"] == "fnd_uc3_ext_001"
        assert inv_data["finding"]["detector"] == "new-external-access"
        assert len(inv_data["finding"]["annotations"]) >= 1

        # Triggering events should be present
        assert len(inv_data["events"]) >= 1
        event_ids = {e["id"] for e in inv_data["events"]}
        assert "evt_gh_perm_change_001" in event_ids

        # POST.md should be present (triage annotated -> routes to next actor)
        assert inv_data["post_md"] is not None
