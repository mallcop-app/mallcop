"""UC-6: Volume anomaly across platforms.

Normal event rate for GitHub is ~20 events/run. A run produces 200 GitHub
events (10x baseline). volume-anomaly detector fires. Triage investigates:
automated release activity. Triage resolves. Baron acks on review.

We mock:
  - GitHub connector (synthetic events -- no live API calls)
  - LLM client (deterministic triage decisions)

We verify:
  - Baseline seeded with normal GitHub volume (~20 push events)
  - 200-event batch triggers volume-anomaly detector (10x spike)
  - Normal-volume batch does NOT trigger volume-anomaly detector
  - Triage resolves the finding as "automated release activity"
  - Ack flow works on the resolved finding
  - Full pipeline: seed -> detect -> escalate -> review -> ack
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
from mallcop.detect import run_detect
from mallcop.schemas import (
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


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
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_github_events(
    count: int,
    actor: str = "ci-bot",
    event_type: str = "push",
    base_time: datetime | None = None,
    id_prefix: str = "evt_gh",
) -> list[Event]:
    """Generate a batch of GitHub events."""
    now = datetime.now(timezone.utc)
    if base_time is None:
        base_time = now - timedelta(hours=1)

    events: list[Event] = []
    for i in range(count):
        ts = base_time + timedelta(seconds=i)
        events.append(Event(
            id=f"{id_prefix}_{i:04d}",
            timestamp=ts,
            ingested_at=now,
            source="github",
            event_type=event_type,
            actor=actor,
            action=f"git.{event_type}",
            target=f"acme-corp/repo-{i % 5}",
            severity=Severity.INFO,
            metadata={"org": "acme-corp"},
            raw={"raw_data": True},
        ))
    return events


def _seed_baseline_with_normal_volume(root: Path) -> None:
    """Seed baseline with ~20 push events from known actors.

    This establishes a normal event rate so volume-anomaly can detect spikes.
    """
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=20)

    # 10 events from admin-user, 10 from devops-bot = 20 total push events
    baseline_events: list[Event] = []
    for actor_name in ["admin-user", "devops-bot"]:
        for j in range(10):
            ts = base_time + timedelta(hours=j * 6)
            baseline_events.append(Event(
                id=f"evt_gh_baseline_{actor_name}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source="github",
                event_type="push",
                actor=actor_name,
                action="git.push",
                target=f"acme-corp/repo-{j % 3}",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ))

    store = JsonlStore(root)
    store.append_events(baseline_events)
    store.update_baseline(baseline_events)


# --- Phase 1: volume-anomaly detector fires on 10x spike ---


class TestVolumeAnomalyDetectorFires:
    """volume-anomaly detector fires when event volume exceeds baseline."""

    def test_10x_spike_triggers_finding(self, tmp_path: Path) -> None:
        """200 push events vs baseline of 20 -> 10x spike -> finding fires."""
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        # Generate 200 push events (10x the baseline of 20)
        spike_events = _make_github_events(
            count=200,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_spike",
        )

        store = JsonlStore(root)
        store.append_events(spike_events)

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        # volume-anomaly should fire for github:push
        vol_findings = [f for f in findings if f.detector == "volume-anomaly"]
        assert len(vol_findings) >= 1, (
            f"Expected volume-anomaly finding, got detectors: "
            f"{[f.detector for f in findings]}"
        )

        vf = vol_findings[0]
        assert vf.severity == Severity.WARN
        assert "github" in vf.title.lower()
        assert "push" in vf.title.lower()
        assert vf.metadata["source"] == "github"
        assert vf.metadata["event_type"] == "push"
        # current_count includes both baseline events (20) and spike events (200)
        assert vf.metadata["current_count"] >= 200
        # baseline is 20 aggregate push events (10 admin-user + 10 devops-bot)
        assert vf.metadata["baseline_count"] == 20

    def test_normal_volume_does_not_trigger(self, tmp_path: Path) -> None:
        """15 push events vs baseline of 20 -> no spike -> no finding."""
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        # Generate 15 events -- well below 3x threshold (would need >60)
        normal_events = _make_github_events(
            count=15,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_normal",
        )

        store = JsonlStore(root)
        store.append_events(normal_events)

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        vol_findings = [f for f in findings if f.detector == "volume-anomaly"]
        assert len(vol_findings) == 0, (
            f"Expected no volume-anomaly finding for normal volume, got: "
            f"{[f.title for f in vol_findings]}"
        )

    def test_just_above_threshold_triggers(self, tmp_path: Path) -> None:
        """61 push events vs baseline of 20 -> just above 3x -> finding fires."""
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        # 61 events > 3.0 * 20 = 60 threshold
        edge_events = _make_github_events(
            count=61,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_edge",
        )

        store = JsonlStore(root)
        store.append_events(edge_events)

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        vol_findings = [f for f in findings if f.detector == "volume-anomaly"]
        assert len(vol_findings) >= 1

    def test_at_threshold_does_not_trigger(self, tmp_path: Path) -> None:
        """Total events exactly at 3x baseline -> no finding (> not >=).

        Baseline has 20 push events. detect() sees ALL events in the store
        (baseline + new). To land exactly at threshold (60 = 3 * 20), we
        need 40 new events so total = 20 + 40 = 60.
        """
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        # 40 new events + 20 baseline = 60 total = exactly 3x -> should not fire
        threshold_events = _make_github_events(
            count=40,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_thresh",
        )

        store = JsonlStore(root)
        store.append_events(threshold_events)

        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        vol_findings = [f for f in findings if f.detector == "volume-anomaly"]
        assert len(vol_findings) == 0


# --- Phase 2: Triage resolves volume anomaly ---


class TestTriageResolvesVolumeAnomaly:
    """Triage actor resolves the volume-anomaly finding as automated activity."""

    def test_triage_resolves_as_automated_release(self, tmp_path: Path) -> None:
        """Triage investigates the spike, determines it's CI bot, resolves."""
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        now = datetime.now(timezone.utc)
        finding = Finding(
            id="fnd_vol_001",
            timestamp=now,
            detector="volume-anomaly",
            event_ids=[f"evt_gh_spike_{i:04d}" for i in range(200)],
            title=(
                "Volume anomaly: github:push -- 200 events vs baseline 20 (10.0x)"
            ),
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={
                "source": "github",
                "event_type": "push",
                "current_count": 200,
                "baseline_count": 20,
                "ratio": 3.0,
            },
        )
        store = JsonlStore(root)
        store.append_findings([finding])

        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.RESOLVED,
                    reason=(
                        "Investigated volume spike: 200 push events from ci-bot "
                        "during large release. All pushes target repos in acme-corp org. "
                        "Automated release activity -- resolving."
                    ),
                ),
                tokens_used=500,
                iterations=2,
            )

        from mallcop.escalate import run_escalate

        result = run_escalate(root, actor_runner=mock_triage)
        assert result["status"] == "ok"
        assert result["findings_processed"] == 1
        assert result["circuit_breaker_triggered"] is False

        # Finding should be resolved with triage annotation
        store2 = JsonlStore(root)
        updated = store2.query_findings()
        assert len(updated) == 1

        fnd = updated[0]
        assert fnd.status == FindingStatus.RESOLVED
        assert len(fnd.annotations) >= 1
        assert fnd.annotations[0].actor == "triage"
        assert fnd.annotations[0].action == "resolved"
        assert "release" in fnd.annotations[0].content.lower()


# --- Phase 3: Ack flow works ---


class TestAckVolumeAnomaly:
    """Baron acks the resolved volume-anomaly finding on review."""

    def test_ack_resolved_volume_anomaly(self, tmp_path: Path) -> None:
        """Baron reviews and acks the triage-resolved finding."""
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        now = datetime.now(timezone.utc)
        # Create spike events so ack can find triggering events
        spike_events = _make_github_events(
            count=200,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_spike",
        )
        store = JsonlStore(root)
        store.append_events(spike_events)

        # Create the resolved finding (as triage would leave it)
        from mallcop.schemas import Annotation

        finding = Finding(
            id="fnd_vol_ack_001",
            timestamp=now,
            detector="volume-anomaly",
            event_ids=["evt_gh_spike_0000", "evt_gh_spike_0001"],
            title="Volume anomaly: github:push -- 200 events vs baseline 20 (10.0x)",
            severity=Severity.WARN,
            status=FindingStatus.RESOLVED,
            annotations=[
                Annotation(
                    actor="triage",
                    timestamp=now,
                    content="Automated release activity. Resolved.",
                    action="resolved",
                    reason="CI bot release",
                ),
            ],
            metadata={
                "source": "github",
                "event_type": "push",
                "current_count": 200,
                "baseline_count": 20,
                "ratio": 3.0,
            },
        )
        store.append_findings([finding])

        # Ack via CLI
        runner = CliRunner()
        result = runner.invoke(
            cli, ["ack", "fnd_vol_ack_001", "--dir", str(root)]
        )
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

        ack_data = json.loads(result.output)
        assert ack_data["status"] == "ok"
        assert ack_data["finding"]["status"] == "acked"
        assert ack_data["baseline_events_applied"] >= 1


# --- Phase 4: Full end-to-end pipeline ---


class TestFullVolumeAnomalyWorkflow:
    """End-to-end: seed baseline -> spike -> detect -> escalate -> review -> ack."""

    def test_full_uc6_pipeline(self, tmp_path: Path) -> None:
        """Full UC-6 pipeline: normal baseline, 10x spike, detect, triage resolves, ack.

        Per UC-6: volume-anomaly fires on 10x spike. Triage investigates and
        resolves as "automated release activity." Baron acks on next review.

        Since triage resolves the finding (status=resolved), review (which shows
        only open findings) won't list it. Baron sees the resolved finding via
        the store and acks it directly.
        """
        root = tmp_path
        _make_config_yaml(root)
        runner = CliRunner()

        # Step 1: Seed baseline with normal GitHub volume
        _seed_baseline_with_normal_volume(root)

        # Step 2: Inject 200 push events (10x spike)
        spike_events = _make_github_events(
            count=200,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_release",
        )
        store = JsonlStore(root)
        store.append_events(spike_events)

        # Step 3: Run detect -- volume-anomaly should fire
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        vol_findings = [f for f in findings if f.detector == "volume-anomaly"]
        assert len(vol_findings) >= 1, (
            f"Expected volume-anomaly finding, got: "
            f"{[(f.detector, f.title) for f in findings]}"
        )

        vf = vol_findings[0]
        assert vf.metadata["source"] == "github"
        assert vf.metadata["event_type"] == "push"
        assert vf.metadata["current_count"] >= 200

        store.append_findings(findings)

        # Step 4: Escalate -- triage resolves volume-anomaly as automated release
        def mock_triage(finding: Finding, **kwargs: Any) -> RunResult:
            if finding.detector == "volume-anomaly":
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.RESOLVED,
                        reason=(
                            "Volume spike caused by ci-bot during large release. "
                            "All 200 push events are automated CI pushes to acme-corp repos. "
                            "Automated release activity -- resolving."
                        ),
                    ),
                    tokens_used=600,
                    iterations=2,
                )
            # Default: escalate unknown findings
            return RunResult(
                resolution=ActorResolution(
                    finding_id=finding.id,
                    action=ResolutionAction.ESCALATED,
                    reason=f"Escalating for review: {finding.title}",
                ),
                tokens_used=400,
                iterations=1,
            )

        from mallcop.escalate import run_escalate

        escalate_result = run_escalate(root, actor_runner=mock_triage)
        assert escalate_result["status"] == "ok"
        assert escalate_result["findings_processed"] >= 1

        # Step 5: Verify triage resolved the volume-anomaly finding
        store2 = JsonlStore(root)
        all_findings = store2.query_findings()
        vol_resolved = [
            f for f in all_findings
            if f.detector == "volume-anomaly" and f.status == FindingStatus.RESOLVED
        ]
        assert len(vol_resolved) >= 1, (
            f"Expected resolved volume-anomaly finding, got: "
            f"{[(f.detector, f.status.value) for f in all_findings]}"
        )

        resolved_fnd = vol_resolved[0]
        assert len(resolved_fnd.annotations) >= 1
        assert resolved_fnd.annotations[0].actor == "triage"
        assert resolved_fnd.annotations[0].action == "resolved"
        assert "release" in resolved_fnd.annotations[0].content.lower()

        # Step 6: Baron acks the resolved volume-anomaly finding
        ack_result = runner.invoke(
            cli, ["ack", resolved_fnd.id, "--dir", str(root)]
        )
        assert ack_result.exit_code == 0, (
            f"Exit {ack_result.exit_code}: {ack_result.output}"
        )
        ack_data = json.loads(ack_result.output)
        assert ack_data["status"] == "ok"
        assert ack_data["finding"]["status"] == "acked"

    def test_learning_mode_suppresses_volume_anomaly(self, tmp_path: Path) -> None:
        """During learning mode, volume-anomaly findings are downgraded to INFO."""
        root = tmp_path
        _make_config_yaml(root)
        _seed_baseline_with_normal_volume(root)

        spike_events = _make_github_events(
            count=200,
            actor="ci-bot",
            event_type="push",
            id_prefix="evt_gh_learn",
        )
        store = JsonlStore(root)
        store.append_events(spike_events)

        all_events = store.query_events()
        baseline = store.get_baseline()

        # With github in learning mode, severity should be INFO
        findings = run_detect(
            all_events, baseline, learning_connectors={"github"}
        )

        vol_findings = [f for f in findings if f.detector == "volume-anomaly"]
        assert len(vol_findings) >= 1

        # All volume findings from github source should be INFO in learning mode
        for vf in vol_findings:
            if vf.metadata.get("source") == "github":
                assert vf.severity == Severity.INFO, (
                    f"Expected INFO severity in learning mode, got {vf.severity}"
                )
