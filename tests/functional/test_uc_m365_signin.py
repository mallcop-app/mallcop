"""UC-4: M365 sign-in anomaly — brute force burst triggers auth-failure-burst detector.

Functional test exercising the M365 sign-in anomaly scenario:

A burst of failed sign-in attempts from an unfamiliar IP. The m365 connector
picks up the sign-in events. auth-failure-burst detector fires (15 failures
in 10 minutes). Triage sees brute force pattern, escalates immediately.

We mock:
  - M365 connector (no live API calls) — events injected directly as recorded fixtures
  - LLM client (deterministic triage decisions — escalate brute force)
  - Teams webhook (capture POST payload instead of real HTTP)

We verify:
  - M365 sign-in failure events are correctly classified
  - auth-failure-burst detector fires on 15+ failures within 10 minutes
  - Triage escalates the brute force finding
  - Review shows the finding with triage annotation
  - Full pipeline: detect -> escalate -> review
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
from mallcop.connectors.m365.connector import _classify_event
from mallcop.connectors._util import make_event_id as _make_event_id
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
    """Write mallcop.yaml configured for M365 sign-in anomaly scenario."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"m365": {"content_types": ["Audit.AzureActiveDirectory"]}},
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


def _make_m365_signin_failure_record(
    record_id: str,
    user_id: str,
    client_ip: str,
    creation_time: str,
) -> dict[str, Any]:
    """Create a raw M365 audit record for a failed sign-in."""
    return {
        "Id": record_id,
        "RecordType": 15,
        "CreationTime": creation_time,
        "Operation": "UserLoginFailed",
        "OrganizationId": "00000000-0000-0000-0000-000000000099",
        "UserType": 0,
        "UserKey": f"key-{record_id}",
        "Workload": "AzureActiveDirectory",
        "ResultStatus": "Failed",
        "UserId": user_id,
        "ClientIP": client_ip,
        "ObjectId": "00000000-0000-0000-0000-000000000099",
        "TargetContextId": "00000000-0000-0000-0000-000000000099",
    }


def _make_m365_signin_success_record(
    record_id: str,
    user_id: str,
    client_ip: str,
    creation_time: str,
) -> dict[str, Any]:
    """Create a raw M365 audit record for a successful sign-in."""
    return {
        "Id": record_id,
        "RecordType": 15,
        "CreationTime": creation_time,
        "Operation": "UserLoggedIn",
        "OrganizationId": "00000000-0000-0000-0000-000000000099",
        "UserType": 0,
        "UserKey": f"key-{record_id}",
        "Workload": "AzureActiveDirectory",
        "ResultStatus": "Success",
        "UserId": user_id,
        "ClientIP": client_ip,
        "ObjectId": "00000000-0000-0000-0000-000000000099",
        "TargetContextId": "00000000-0000-0000-0000-000000000099",
    }


def _record_to_event(record: dict[str, Any], now: datetime) -> Event:
    """Convert a raw M365 audit record to a normalized Event, matching M365Connector.poll logic."""
    event_type, severity = _classify_event(record)
    return Event(
        id=_make_event_id(record["Id"]),
        timestamp=datetime.fromisoformat(
            record["CreationTime"].replace("Z", "+00:00")
            if record["CreationTime"].endswith("Z")
            else record["CreationTime"]
        ).replace(tzinfo=timezone.utc),
        ingested_at=now,
        source="m365",
        event_type=event_type,
        actor=record.get("UserId", "unknown"),
        action=record.get("Operation", ""),
        target=record.get("ObjectId", ""),
        severity=severity,
        metadata={
            "workload": record.get("Workload", ""),
            "record_type": record.get("RecordType", 0),
            "organization_id": record.get("OrganizationId", ""),
            "result_status": record.get("ResultStatus", ""),
            "ip_address": record.get("ClientIP", ""),
        },
        raw=record,
    )


def _seed_baseline_with_known_actors(root: Path) -> tuple[list[Event], datetime]:
    """Seed baseline with known M365 actors from 20+ days ago.

    Returns (known_events, now).
    """
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=20)

    known_events: list[Event] = []
    known_actors = ["admin@acme-corp.dev", "user@acme-corp.dev"]
    for i, actor in enumerate(known_actors):
        for j in range(5):
            ts = base_time + timedelta(hours=i * 6 + j)
            known_events.append(Event(
                id=f"evt_known_m365_{actor.split('@')[0]}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source="m365",
                event_type="sign_in_success",
                actor=actor,
                action="UserLoggedIn",
                target="/tenants/tenant-001",
                severity=Severity.INFO,
                metadata={
                    "workload": "AzureActiveDirectory",
                    "record_type": 15,
                    "ip_address": f"10.0.{i}.1",
                },
                raw={"raw_data": True},
            ))

    store = JsonlStore(root)
    store.append_events(known_events)
    store.update_baseline(known_events)

    return known_events, now


def _inject_brute_force_burst(
    root: Path,
    now: datetime,
    attacker_ip: str = "198.51.100.50",
    target_user: str = "admin@acme-corp.dev",
    failure_count: int = 18,
) -> list[Event]:
    """Inject a burst of failed sign-in attempts within 10 minutes.

    Creates failure_count failed login events from attacker_ip targeting
    target_user, spaced ~30 seconds apart (all within a 10-minute window).
    """
    burst_start = now - timedelta(minutes=15)
    records: list[dict[str, Any]] = []

    for i in range(failure_count):
        ts = burst_start + timedelta(seconds=i * 30)
        record = _make_m365_signin_failure_record(
            record_id=f"brute-{i:03d}",
            user_id=target_user,
            client_ip=attacker_ip,
            creation_time=ts.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        records.append(record)

    events = [_record_to_event(r, now) for r in records]

    store = JsonlStore(root)
    store.append_events(events)

    return events


# --- Tests ---


class TestM365EventClassification:
    """M365 sign-in events are correctly classified."""

    def test_failed_login_classified_as_sign_in_failure(self) -> None:
        """UserLoginFailed operation maps to sign_in_failure event type."""
        record = _make_m365_signin_failure_record(
            record_id="test-001",
            user_id="attacker@evil.com",
            client_ip="198.51.100.50",
            creation_time="2026-03-05T14:30:00",
        )
        event_type, severity = _classify_event(record)
        assert event_type == "sign_in_failure"
        assert severity == Severity.INFO

    def test_successful_login_classified_as_sign_in_success(self) -> None:
        """UserLoggedIn with Success maps to sign_in_success."""
        record = _make_m365_signin_success_record(
            record_id="test-002",
            user_id="admin@acme-corp.dev",
            client_ip="10.0.0.1",
            creation_time="2026-03-05T14:30:00",
        )
        event_type, severity = _classify_event(record)
        assert event_type == "sign_in_success"
        assert severity == Severity.INFO


class TestAuthFailureBurstDetection:
    """auth-failure-burst detector fires on 15+ failures within window."""

    def test_burst_triggers_finding(self, tmp_path: Path) -> None:
        """18 failed logins in 10 minutes triggers auth-failure-burst detector."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        burst_events = _inject_brute_force_burst(root, now, failure_count=18)

        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()

        findings = run_detect(all_events, baseline, learning_connectors=set())

        # auth-failure-burst should fire (18 >= threshold of 10)
        burst_findings = [
            f for f in findings if f.detector == "auth-failure-burst"
        ]
        assert len(burst_findings) >= 1, (
            f"Expected auth-failure-burst finding, got detectors: "
            f"{[f.detector for f in findings]}"
        )

        bf = burst_findings[0]
        assert bf.severity in (Severity.WARN, Severity.CRITICAL)
        assert bf.metadata["count"] >= 15
        assert len(bf.event_ids) >= 15

    def test_below_threshold_no_finding(self, tmp_path: Path) -> None:
        """5 failed logins should NOT trigger auth-failure-burst (threshold=10)."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        _inject_brute_force_burst(root, now, failure_count=5)

        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()

        findings = run_detect(all_events, baseline, learning_connectors=set())

        burst_findings = [
            f for f in findings if f.detector == "auth-failure-burst"
        ]
        assert len(burst_findings) == 0, (
            f"Should not fire for only 5 failures, got: {burst_findings}"
        )

    def test_burst_severity_escalates_at_critical_threshold(self, tmp_path: Path) -> None:
        """50+ failures should produce CRITICAL severity."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        _inject_brute_force_burst(root, now, failure_count=55)

        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()

        findings = run_detect(all_events, baseline, learning_connectors=set())

        burst_findings = [
            f for f in findings if f.detector == "auth-failure-burst"
        ]
        assert len(burst_findings) >= 1
        # Default critical_threshold is 50
        assert burst_findings[0].severity == Severity.CRITICAL

    def test_learning_mode_suppresses_severity(self, tmp_path: Path) -> None:
        """Burst during learning mode gets severity forced to INFO."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        _inject_brute_force_burst(root, now, failure_count=18)

        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()

        # m365 is in learning mode
        findings = run_detect(all_events, baseline, learning_connectors={"m365"})

        burst_findings = [
            f for f in findings if f.detector == "auth-failure-burst"
        ]
        assert len(burst_findings) >= 1
        # Learning mode forces severity to INFO
        assert burst_findings[0].severity == Severity.INFO


class TestTriageEscalatesBruteForce:
    """Triage actor sees brute force pattern and escalates."""

    def test_escalate_processes_burst_finding(self, tmp_path: Path) -> None:
        """Escalation routes burst finding through mock triage, which escalates."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        burst_events = _inject_brute_force_burst(root, now, failure_count=18)

        # Run detect to produce findings
        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())
        store.append_findings(findings)

        burst_findings = [f for f in findings if f.detector == "auth-failure-burst"]
        assert len(burst_findings) >= 1

        # Mock triage: sees brute force, escalates
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        f"Brute force pattern detected: {finding.metadata.get('count', 0)} "
                        f"auth failures. Escalating immediately."
                    ),
                ),
                tokens_used=600,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        result = run_escalate(root, actor_runner=mock_triage)

        assert result["status"] == "ok"
        assert result["findings_processed"] >= 1
        assert result["circuit_breaker_triggered"] is False

        # Verify finding has triage annotation with escalation
        # Create fresh store to see updates from run_escalate
        fresh_store = JsonlStore(root)
        updated_findings = fresh_store.query_findings()
        burst_updated = [
            f for f in updated_findings if f.detector == "auth-failure-burst"
        ]
        assert len(burst_updated) >= 1
        bf = burst_updated[0]
        assert len(bf.annotations) >= 1
        assert bf.annotations[0].actor == "triage"
        assert bf.annotations[0].action == "escalated"
        assert "brute force" in bf.annotations[0].content.lower()

    def test_costs_tracked_after_triage(self, tmp_path: Path) -> None:
        """costs.jsonl records token spend from triage processing."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        _inject_brute_force_burst(root, now, failure_count=18)

        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())
        store.append_findings(findings)

        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Brute force. Escalating.",
                ),
                tokens_used=500,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        run_escalate(root, actor_runner=mock_triage)

        costs_path = root / "costs.jsonl"
        assert costs_path.exists()
        cost_lines = costs_path.read_text().strip().split("\n")
        last_cost = json.loads(cost_lines[-1])
        assert last_cost["actors_invoked"] is True
        assert last_cost["tokens_used"] > 0


class TestReviewShowsBurstFinding:
    """Review command shows burst finding with triage annotation."""

    def test_review_shows_burst_with_annotation(self, tmp_path: Path) -> None:
        """Review lists auth-failure-burst finding with triage escalation note."""
        root = tmp_path
        _make_config_yaml(root)
        _known_events, now = _seed_baseline_with_known_actors(root)
        _inject_brute_force_burst(root, now, failure_count=18)

        # Detect
        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())
        store.append_findings(findings)

        # Escalate with mock triage
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason="Brute force attack from unfamiliar IP. Escalating.",
                ),
                tokens_used=500,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        run_escalate(root, actor_runner=mock_triage)

        # Review
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--dir", str(root)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)

        assert data["command"] == "review"
        assert data["status"] == "ok"

        # Burst finding should appear in warn severity group
        findings_by_sev = data["findings_by_severity"]
        all_review_findings = []
        for sev, flist in findings_by_sev.items():
            all_review_findings.extend(flist)

        burst_in_review = [
            f for f in all_review_findings
            if f.get("detector") == "auth-failure-burst"
        ]
        assert len(burst_in_review) >= 1, (
            f"Expected auth-failure-burst in review, got: "
            f"{[f.get('detector') for f in all_review_findings]}"
        )

        bf = burst_in_review[0]
        assert len(bf["annotations"]) >= 1
        assert bf["annotations"][0]["actor"] == "triage"
        assert "brute force" in bf["annotations"][0]["content"].lower()


class TestFullM365SigninAnomalyWorkflow:
    """End-to-end: M365 burst -> detect -> escalate -> review -> investigate."""

    def test_full_uc4_pipeline(self, tmp_path: Path) -> None:
        """Full UC-4 workflow: M365 sign-in burst detected, triaged, reviewed."""
        root = tmp_path
        _make_config_yaml(root)
        runner = CliRunner()

        # Step 1: Seed baseline with known M365 actors
        _known_events, now = _seed_baseline_with_known_actors(root)

        # Step 2: Inject brute force burst (18 failures in ~9 minutes)
        burst_events = _inject_brute_force_burst(
            root, now,
            attacker_ip="198.51.100.50",
            target_user="admin@acme-corp.dev",
            failure_count=18,
        )

        # Step 3: Run detect
        from mallcop.detect import run_detect

        store = JsonlStore(root)
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # auth-failure-burst should fire
        burst_findings = [f for f in findings if f.detector == "auth-failure-burst"]
        assert len(burst_findings) >= 1, (
            f"auth-failure-burst should fire on 18 failures, got detectors: "
            f"{[f.detector for f in findings]}"
        )
        store.append_findings(findings)

        finding_id = burst_findings[0].id

        # Step 4: Escalate — triage sees brute force, escalates
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        f"Brute force pattern: {finding.metadata.get('count', 0)} "
                        f"auth failures from unfamiliar IP. Escalating immediately."
                    ),
                ),
                tokens_used=600,
                iterations=1,
            )

        from mallcop.escalate import run_escalate
        escalate_result = run_escalate(root, actor_runner=mock_triage)

        assert escalate_result["status"] == "ok"
        assert escalate_result["findings_processed"] >= 1

        # Step 5: Review — human opens session
        result = runner.invoke(cli, ["review", "--dir", str(root)])
        assert result.exit_code == 0
        review_data = json.loads(result.output)

        assert review_data["status"] == "ok"
        all_sev_findings = []
        for sev, flist in review_data["findings_by_severity"].items():
            all_sev_findings.extend(flist)

        burst_in_review = [
            f for f in all_sev_findings
            if f.get("detector") == "auth-failure-burst"
        ]
        assert len(burst_in_review) >= 1
        assert len(burst_in_review[0]["annotations"]) >= 1
        assert burst_in_review[0]["annotations"][0]["action"] == "escalated"

        # POST.md should be loaded (triage escalated -> next actor in chain)
        assert review_data["post_md"] is not None

        # Step 6: Investigate the burst finding
        result = runner.invoke(cli, ["investigate", finding_id, "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        inv_data = json.loads(result.output)

        assert inv_data["status"] == "ok"
        assert inv_data["finding"]["id"] == finding_id
        assert inv_data["finding"]["detector"] == "auth-failure-burst"
        # Should have triggering events
        assert len(inv_data["events"]) >= 1

        # Step 7: Verify costs were tracked
        costs_path = root / "costs.jsonl"
        assert costs_path.exists()
        cost_lines = costs_path.read_text().strip().split("\n")
        last_cost = json.loads(cost_lines[-1])
        assert last_cost["actors_invoked"] is True
        assert last_cost["tokens_used"] > 0

        # Step 8: Annotate finding with investigation conclusion
        result = runner.invoke(
            cli,
            [
                "annotate", finding_id,
                "Confirmed brute force from 198.51.100.50. Blocking IP at firewall. "
                "Account admin@acme-corp.dev not compromised — all attempts failed.",
                "--author", "admin-user",
                "--dir", str(root),
            ],
        )
        assert result.exit_code == 0
        ann_data = json.loads(result.output)
        assert ann_data["status"] == "ok"

        # Verify final state
        final_store = JsonlStore(root)
        final_findings = final_store.query_findings()
        final_burst = [f for f in final_findings if f.id == finding_id][0]

        # Should have triage + human annotations
        assert len(final_burst.annotations) >= 2
        triage_anns = [a for a in final_burst.annotations if a.actor == "triage"]
        assert len(triage_anns) >= 1
        human_anns = [a for a in final_burst.annotations if a.actor == "admin-user"]
        assert len(human_anns) == 1
        assert "brute force" in human_anns[0].content.lower()
