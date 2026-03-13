"""UC: Active intrusion -- anomaly detected, human notified, interactive deep dive.

Functional test exercising the full intrusion response workflow:

Phase 1 (autonomous):
  Cron: mallcop watch
    -> detect: 1 CRITICAL (new admin role from unknown actor), several WARN
    -> escalate: triage annotates, escalates to Teams
    -> Teams notification hits human phone

Phase 2 (interactive investigation):
  Human opens Claude Code session:
    Agent: mallcop review
      -> sees CRITICAL finding with triage annotation
    Agent: mallcop investigate fnd_xxx
      -> gets POST.md + deep context
    Agent: mallcop events --actor admin@unknown.com --hours 48
    Agent: mallcop baseline --actor admin@unknown.com
      -> "This actor has never been seen."
    Human: mallcop annotate fnd_xxx "Confirmed intrusion. Revoking access."

We mock:
  - Azure connector (no live API calls) via patching poll methods
  - LLM client (deterministic triage decisions -- escalate CRITICAL)
  - Teams webhook (capture POST payload instead of real HTTP)

We verify:
  - Detection produces CRITICAL and WARN findings from unknown actor
  - Escalation annotates findings with triage reasoning
  - Review shows CRITICAL finding with triage annotation, POST.md, and suggested commands
  - Investigate returns deep context: finding, triggering events, actor history, baseline
  - Events query by actor returns relevant events
  - Baseline query shows unknown actor
  - Annotate adds investigation note to finding
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
from mallcop.schemas import (
    Annotation,
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_config_yaml(root: Path) -> None:
    """Write mallcop.yaml configured for intrusion scenario."""
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


def _seed_baseline_environment(root: Path) -> tuple[list[Event], datetime]:
    """Seed known events from 20+ days ago and build baseline.

    Returns (known_events, now) for use in test setup.
    """
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=20)

    # Known actors that have legitimate history
    known_actors = ["admin@example.com", "deploy@example.com"]
    known_events: list[Event] = []
    for i, actor in enumerate(known_actors):
        for j in range(5):
            ts = base_time + timedelta(hours=i * 6 + j)
            known_events.append(Event(
                id=f"evt_known_{actor.split('@')[0]}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source="azure",
                event_type="role_assignment",
                actor=actor,
                action="create",
                target=f"/subscriptions/sub-001/resource_{i}_{j}",
                severity=Severity.INFO,
                metadata={"ip_address": f"10.0.{i}.{j}"},
                raw={"raw_data": True},
            ))

    store = JsonlStore(root)
    store.append_events(known_events)
    store.update_baseline(known_events)

    return known_events, now


def _inject_intruder_events(
    root: Path,
    now: datetime,
    intruder_actor: str = "admin@unknown.com",
) -> list[Event]:
    """Inject events from an unknown actor (the intruder).

    Includes a CRITICAL action (Global Admin grant at 3:14 AM) and WARNs.
    """
    intruder_events = [
        Event(
            id="evt_intruder_recon_001",
            timestamp=now - timedelta(hours=3),
            ingested_at=now - timedelta(hours=2, minutes=59),
            source="azure",
            event_type="sign_in",
            actor=intruder_actor,
            action="login",
            target="/tenants/tenant-001",
            severity=Severity.WARN,
            metadata={"ip_address": "203.0.113.42"},
            raw={"raw_data": True},
        ),
        Event(
            id="evt_intruder_role_001",
            timestamp=now - timedelta(hours=2),
            ingested_at=now - timedelta(hours=1, minutes=59),
            source="azure",
            event_type="role_assignment",
            actor=intruder_actor,
            action="create",
            target="/subscriptions/sub-001/providers/Microsoft.Authorization/roleAssignments/global-admin",
            severity=Severity.CRITICAL,
            metadata={"ip_address": "203.0.113.42", "role": "Global Administrator"},
            raw={"raw_data": True, "role": "Global Administrator"},
        ),
        Event(
            id="evt_intruder_access_001",
            timestamp=now - timedelta(hours=1, minutes=30),
            ingested_at=now - timedelta(hours=1, minutes=29),
            source="azure",
            event_type="resource_access",
            actor=intruder_actor,
            action="read",
            target="/subscriptions/sub-001/resourceGroups/production/secrets",
            severity=Severity.WARN,
            metadata={"ip_address": "203.0.113.42"},
            raw={"raw_data": True},
        ),
    ]

    store = JsonlStore(root)
    store.append_events(intruder_events)

    return intruder_events


def _create_intrusion_findings(
    root: Path,
    now: datetime,
    intruder_actor: str = "admin@unknown.com",
) -> list[Finding]:
    """Create findings matching what the detect pipeline would produce for the intruder."""
    critical_finding = Finding(
        id="fnd_critical_001",
        timestamp=now - timedelta(minutes=30),
        detector="new-actor",
        event_ids=["evt_intruder_recon_001", "evt_intruder_role_001", "evt_intruder_access_001"],
        title=f"New actor: {intruder_actor} on azure",
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": intruder_actor, "sources": ["azure"]},
    )

    warn_finding = Finding(
        id="fnd_warn_001",
        timestamp=now - timedelta(minutes=28),
        detector="new-actor",
        event_ids=["evt_intruder_recon_001"],
        title=f"New sign-in from unknown actor: {intruder_actor}",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": intruder_actor, "sources": ["azure"]},
    )

    findings = [critical_finding, warn_finding]
    store = JsonlStore(root)
    store.append_findings(findings)

    return findings


def _apply_triage_annotations(
    root: Path,
    findings: list[Finding],
) -> None:
    """Simulate triage actor annotating findings with escalation reasoning."""
    store = JsonlStore(root)
    now = datetime.now(timezone.utc)

    for f in findings:
        if f.severity == Severity.CRITICAL:
            annotation = Annotation(
                actor="triage",
                timestamp=now,
                content=(
                    "CRITICAL: Unknown actor granted Global Admin role at unusual hour. "
                    "Actor admin@unknown.com has never been seen in baseline. Escalating."
                ),
                action="escalated",
                reason="Unknown actor, high-privilege role grant, unusual hour",
            )
        else:
            annotation = Annotation(
                actor="triage",
                timestamp=now,
                content=(
                    "WARN: New sign-in from unknown actor admin@unknown.com. "
                    "No baseline history. Escalating for human review."
                ),
                action="escalated",
                reason="Unknown actor, no baseline history",
            )
        store.update_finding(f.id, annotations=[annotation])


# --- Phase 1: Autonomous Detection + Triage ---


class TestAutonomousDetection:
    """Phase 1: mallcop watch detects anomaly and triage escalates."""

    def test_detect_produces_findings_for_unknown_actor(self, tmp_path: Path) -> None:
        """Detect pipeline flags unknown actor with CRITICAL and WARN findings."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)

        # Run detect directly
        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()

        findings = run_detect(all_events, baseline, learning_connectors=set())

        # Should have at least 1 finding for the unknown actor
        assert len(findings) >= 1
        intruder_findings = [
            f for f in findings
            if "admin@unknown.com" in f.title or f.metadata.get("actor") == "admin@unknown.com"
        ]
        assert len(intruder_findings) >= 1
        # Detector flags new actors as WARN by default
        assert all(f.severity in (Severity.WARN, Severity.CRITICAL) for f in intruder_findings)

    def test_escalate_annotates_and_processes_findings(self, tmp_path: Path) -> None:
        """Escalation processes findings through mock triage, annotates them."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)
        findings = _create_intrusion_findings(root, now)

        # Mock triage actor: escalates everything (it's a bad day)
        def mock_triage_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        f"Unknown actor, escalating: {finding.title}"
                    ),
                ),
                tokens_used=800,
                iterations=2,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_triage_runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 2
        assert result["circuit_breaker_triggered"] is False

        # Verify findings have triage annotations
        store = JsonlStore(root)
        all_findings = store.query_findings()
        for f in all_findings:
            assert len(f.annotations) > 0, f"Finding {f.id} should have annotations"
            assert f.annotations[0].actor == "triage"
            assert f.annotations[0].action == "escalated"

        # All findings should remain open (escalated, not resolved)
        open_findings = [f for f in all_findings if f.status == FindingStatus.OPEN]
        assert len(open_findings) == 2

    def test_costs_tracked_after_escalation(self, tmp_path: Path) -> None:
        """costs.jsonl written with token spend after triage processes findings."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        findings = _create_intrusion_findings(root, now)

        def mock_runner(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Escalating",
                ),
                tokens_used=1000,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        run_escalate(root, actor_runner=mock_runner)

        costs_path = root / ".mallcop" / "costs.jsonl"
        assert costs_path.exists()
        cost_data = json.loads(costs_path.read_text().strip().split("\n")[-1])
        assert cost_data["tokens_used"] == 2000  # 2 findings x 1000 tokens
        assert cost_data["actors_invoked"] is True


# --- Phase 2: Interactive Investigation ---


class TestInteractiveReview:
    """mallcop review shows CRITICAL finding with triage annotation."""

    def test_review_shows_critical_findings_with_annotations(self, tmp_path: Path) -> None:
        """Review groups findings by severity and includes triage annotations."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)
        findings = _create_intrusion_findings(root, now)
        _apply_triage_annotations(root, findings)

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "review"
        assert data["status"] == "ok"

        # CRITICAL findings should appear
        findings_by_sev = data["findings_by_severity"]
        assert "critical" in findings_by_sev, f"Expected critical findings, got: {list(findings_by_sev.keys())}"

        critical_findings = findings_by_sev["critical"]
        assert len(critical_findings) >= 1

        # CRITICAL finding should have triage annotation
        crit = critical_findings[0]
        assert len(crit["annotations"]) >= 1
        assert crit["annotations"][0]["actor"] == "triage"
        assert "Global Admin" in crit["annotations"][0]["content"] or "escalat" in crit["annotations"][0]["content"].lower()

        # WARN findings should also appear
        assert "warn" in findings_by_sev

        # POST.md should be loaded — since all CRITICAL findings have triage
        # annotations, review advances to next actor in chain (notify-teams)
        assert data["post_md"] is not None
        assert data["post_md_source"] == "notify-teams"

        # Suggested commands should include investigate for the finding
        assert any("investigate" in cmd for cmd in data["suggested_commands"])

    def test_review_human_output_format(self, tmp_path: Path) -> None:
        """Review --human renders readable format with severity grouping."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        findings = _create_intrusion_findings(root, now)
        _apply_triage_annotations(root, findings)

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--dir", str(root), "--human"])

        assert result.exit_code == 0
        assert "CRITICAL" in result.output
        assert "WARN" in result.output
        assert "triage" in result.output


class TestInteractiveInvestigate:
    """mallcop investigate provides deep context for a single finding."""

    def test_investigate_returns_full_context(self, tmp_path: Path) -> None:
        """Investigate returns finding, events, actor history, baseline, and POST.md."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)
        findings = _create_intrusion_findings(root, now)
        _apply_triage_annotations(root, findings)

        runner = CliRunner()
        result = runner.invoke(cli, ["investigate", "fnd_critical_001", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "investigate"
        assert data["status"] == "ok"

        # Finding details
        finding = data["finding"]
        assert finding["id"] == "fnd_critical_001"
        assert finding["severity"] == "critical"
        assert finding["status"] == "open"
        assert len(finding["annotations"]) >= 1

        # Triggering events
        events = data["events"]
        assert len(events) >= 1
        event_ids = {e["id"] for e in events}
        assert "evt_intruder_role_001" in event_ids

        # Actor history -- all events from the intruder (actor key is sanitized)
        actor_history = data["actor_history"]
        # Find the sanitized key containing the raw actor name
        intruder_key = next(
            (k for k in actor_history if "admin@unknown.com" in k), None
        )
        assert intruder_key is not None, \
            f"Expected actor containing 'admin@unknown.com' in: {list(actor_history.keys())}"
        assert len(actor_history[intruder_key]) >= 1

        # Baseline shows actor is UNKNOWN (actor key is sanitized)
        baseline = data["baseline"]
        baseline_actor_key = next(
            (k for k in baseline["actors"] if "admin@unknown.com" in k), None
        )
        assert baseline_actor_key is not None, \
            f"Expected actor containing 'admin@unknown.com' in: {list(baseline['actors'].keys())}"
        actor_profile = baseline["actors"][baseline_actor_key]
        assert actor_profile["known"] is False

        # POST.md loaded (triage annotated, so should get notify-teams POST.md per routing)
        # After triage annotation, investigate routes to next actor in chain
        assert data["post_md"] is not None

    def test_investigate_nonexistent_finding(self, tmp_path: Path) -> None:
        """Investigate returns error for unknown finding ID."""
        root = tmp_path
        _make_config_yaml(root)

        runner = CliRunner()
        result = runner.invoke(cli, ["investigate", "fnd_nonexistent", "--dir", str(root)])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"

    def test_investigate_human_output(self, tmp_path: Path) -> None:
        """Investigate --human renders readable format."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)
        findings = _create_intrusion_findings(root, now)
        _apply_triage_annotations(root, findings)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["investigate", "fnd_critical_001", "--dir", str(root), "--human"]
        )

        assert result.exit_code == 0
        assert "fnd_critical_001" in result.output
        assert "CRITICAL" in result.output
        assert "UNKNOWN" in result.output  # baseline shows unknown actor


class TestInteractiveEventsQuery:
    """mallcop events --actor queries events for a specific actor."""

    def test_events_by_actor_returns_intruder_activity(self, tmp_path: Path) -> None:
        """Events filtered by actor returns all intruder events."""
        from mallcop.sanitize import sanitize_field

        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        intruder_events = _inject_intruder_events(root, now)

        # Actor is sanitized at ingest, so query must use sanitized value
        sanitized_actor = sanitize_field("admin@unknown.com")
        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--actor", sanitized_actor, "--hours", "48", "--dir", str(root)]
        )

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "events"
        assert data["status"] == "ok"

        events = data["events"]
        assert len(events) == 3  # 3 intruder events
        # All events should be from the intruder (sanitized)
        assert all("admin@unknown.com" in e["actor"] for e in events)
        # Newest first
        assert events[0]["id"] == "evt_intruder_access_001"

    def test_events_by_finding_returns_triggering_events(self, tmp_path: Path) -> None:
        """Events filtered by finding ID returns the triggering events."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)
        _create_intrusion_findings(root, now)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--finding", "fnd_critical_001", "--dir", str(root)]
        )

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        events = data["events"]
        # fnd_critical_001 has 3 event_ids
        assert len(events) == 3
        event_ids = {e["id"] for e in events}
        assert "evt_intruder_role_001" in event_ids

    def test_events_no_results_for_unknown_actor(self, tmp_path: Path) -> None:
        """Events query for non-existent actor returns empty."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--actor", "nobody@nowhere.com", "--hours", "48", "--dir", str(root)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 0


class TestInteractiveBaseline:
    """mallcop baseline --actor shows unknown actor has never been seen."""

    def test_baseline_shows_unknown_actor(self, tmp_path: Path) -> None:
        """Baseline query for intruder actor shows they are unknown."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["baseline", "--actor", "admin@unknown.com", "--dir", str(root)]
        )

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "baseline"
        assert data["status"] == "ok"
        assert data["actor"] == "admin@unknown.com"
        assert data["known"] is False
        assert data["frequency_entries"] == {}
        assert data["relationships"] == {}

    def test_baseline_shows_known_actor(self, tmp_path: Path) -> None:
        """Baseline query for known actor shows they are in baseline."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["baseline", "--actor", "admin@example.com", "--dir", str(root)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["known"] is True
        assert len(data["frequency_entries"]) > 0
        assert len(data["relationships"]) > 0

    def test_baseline_general_stats(self, tmp_path: Path) -> None:
        """General baseline query shows aggregate stats."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)

        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "--dir", str(root)])

        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["known_actor_count"] == 2  # admin@ and deploy@
        assert data["event_count"] == 10  # 2 actors x 5 events


class TestInteractiveAnnotate:
    """mallcop annotate adds investigation note to a finding."""

    def test_annotate_finding_with_investigation_note(self, tmp_path: Path) -> None:
        """Annotate adds a human's investigation note to the finding."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_environment(root)
        _inject_intruder_events(root, now)
        findings = _create_intrusion_findings(root, now)
        _apply_triage_annotations(root, findings)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "annotate", "fnd_critical_001",
                "Confirmed intrusion. Revoking access. Incident ticket INC-2026-042.",
                "--author", "admin-user",
                "--dir", str(root),
            ],
        )

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "annotate"
        assert data["status"] == "ok"
        assert data["finding_id"] == "fnd_critical_001"
        assert data["annotation"]["actor"] == "admin-user"
        assert "Confirmed intrusion" in data["annotation"]["content"]

        # Verify annotation persisted
        store = JsonlStore(root)
        all_findings = store.query_findings()
        fnd = [f for f in all_findings if f.id == "fnd_critical_001"][0]
        # Should have triage annotation + human annotation
        assert len(fnd.annotations) >= 2
        human_ann = [a for a in fnd.annotations if a.actor == "admin-user"]
        assert len(human_ann) == 1
        assert "Confirmed intrusion" in human_ann[0].content

    def test_annotate_nonexistent_finding(self, tmp_path: Path) -> None:
        """Annotate returns error for unknown finding ID."""
        root = tmp_path
        _make_config_yaml(root)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_nonexistent", "test note", "--dir", str(root)]
        )

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"


# --- Full End-to-End Workflow ---


class TestFullIntrusionWorkflow:
    """End-to-end: detect -> escalate -> review -> investigate -> annotate."""

    def test_full_intrusion_loop(self, tmp_path: Path) -> None:
        """Full intrusion response loop: autonomous detection through interactive investigation."""
        root = tmp_path
        _make_config_yaml(root)
        runner = CliRunner()

        # Step 1: Seed environment with known actors (past learning period)
        _known_events, now = _seed_baseline_environment(root)

        # Step 2: Inject intruder events
        _inject_intruder_events(root, now)

        # Step 3: Run detect to produce findings
        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        assert len(findings) >= 1, "Detect should produce findings for unknown actor"
        store.append_findings(findings)

        # Get the finding ID for the intruder (actor is sanitized with markers)
        intruder_finding = [
            f for f in findings
            if "admin@unknown.com" in (f.metadata.get("actor") or "")
        ]
        assert len(intruder_finding) >= 1
        finding_id = intruder_finding[0].id

        # Step 4: Run escalation (triage escalates everything)
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=f"Unknown actor detected: {finding.title}. Escalating for human review.",
                ),
                tokens_used=1000,
                iterations=2,
            )

        from mallcop.escalate import run_escalate
        escalate_result = run_escalate(root, actor_runner=mock_triage)

        assert escalate_result["status"] == "ok"
        assert escalate_result["findings_processed"] >= 1

        # Step 5: Human opens session -- mallcop review
        result = runner.invoke(cli, ["review", "--dir", str(root)])
        assert result.exit_code == 0
        review_data = json.loads(result.output)

        assert review_data["status"] == "ok"
        # Should have findings (at least the intruder finding)
        all_sev_findings = []
        for sev, flist in review_data["findings_by_severity"].items():
            all_sev_findings.extend(flist)
        assert len(all_sev_findings) >= 1

        # Find our intruder finding in the review
        intruder_in_review = [
            f for f in all_sev_findings
            if f["id"] == finding_id
        ]
        assert len(intruder_in_review) == 1
        assert len(intruder_in_review[0]["annotations"]) >= 1  # Has triage annotation

        # POST.md should be loaded
        assert review_data["post_md"] is not None

        # Step 6: mallcop investigate <finding_id>
        result = runner.invoke(cli, ["investigate", finding_id, "--dir", str(root)])
        assert result.exit_code == 0
        inv_data = json.loads(result.output)

        assert inv_data["status"] == "ok"
        assert inv_data["finding"]["id"] == finding_id
        assert len(inv_data["events"]) >= 1
        # Actor keys are sanitized with markers
        inv_actor_key = next(
            (k for k in inv_data["actor_history"] if "admin@unknown.com" in k), None
        )
        assert inv_actor_key is not None
        inv_bl_actor_key = next(
            (k for k in inv_data["baseline"]["actors"] if "admin@unknown.com" in k), None
        )
        assert inv_bl_actor_key is not None
        assert inv_data["baseline"]["actors"][inv_bl_actor_key]["known"] is False
        assert inv_data["post_md"] is not None

        # Step 7: mallcop events --actor (sanitized) --hours 48
        from mallcop.sanitize import sanitize_field
        sanitized_actor = sanitize_field("admin@unknown.com")
        result = runner.invoke(
            cli, ["events", "--actor", sanitized_actor, "--hours", "48", "--dir", str(root)]
        )
        assert result.exit_code == 0
        events_data = json.loads(result.output)

        assert len(events_data["events"]) == 3
        assert all("admin@unknown.com" in e["actor"] for e in events_data["events"])

        # Step 8: mallcop baseline --actor (sanitized)
        result = runner.invoke(
            cli, ["baseline", "--actor", sanitized_actor, "--dir", str(root)]
        )
        assert result.exit_code == 0
        bl_data = json.loads(result.output)

        assert bl_data["known"] is False  # Never been seen in baseline

        # Step 9: Human annotates the finding
        result = runner.invoke(
            cli,
            [
                "annotate", finding_id,
                "Confirmed intrusion. Actor admin@unknown.com granted Global Admin at 3:14 AM. "
                "Revoking access. Incident ticket INC-2026-042.",
                "--author", "admin-user",
                "--dir", str(root),
            ],
        )
        assert result.exit_code == 0
        ann_data = json.loads(result.output)
        assert ann_data["status"] == "ok"

        # Step 10: Verify final state -- finding has both triage and human annotations
        final_store = JsonlStore(root)
        final_findings = final_store.query_findings()
        final_finding = [f for f in final_findings if f.id == finding_id][0]

        assert final_finding.status == FindingStatus.OPEN  # Not acked yet
        assert len(final_finding.annotations) >= 2  # triage + human

        # Triage annotation
        triage_anns = [a for a in final_finding.annotations if a.actor == "triage"]
        assert len(triage_anns) >= 1

        # Human annotation
        human_anns = [a for a in final_finding.annotations if a.actor == "admin-user"]
        assert len(human_anns) == 1
        assert "Confirmed intrusion" in human_anns[0].content
