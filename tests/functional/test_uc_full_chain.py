"""UC: Full actor chain — end-to-end escalation through triage → investigate → notify-teams.

Functional test proving the full actor chain works with batch processing and channel delivery:

- Multiple WARN findings seeded → run_escalate with mock LLM → triage escalates → investigate
  escalates → notify-teams delivers via Teams webhook (mocked HTTP)
- Annotations on findings carry correct actor names through the chain
- Budget exhaustion produces correct mallcop-budget annotations on later findings

Also contains a CliRunner-based full pipeline test:
- init → scan (mock connector) → detect → escalate (mock LLM resolves) → review
- Verifies exit codes, JSON shapes, on-disk state at each step

We mock:
  - LLMClient (deterministic escalation responses)
  - HTTP layer (requests.post for Teams webhook)
  - GitHub connector poll (returns synthetic collaborator_added events)

We verify:
  - Both findings flow through triage → investigate → notify-teams
  - Teams webhook receives POST with correct payload
  - Annotations have correct actor names
  - Budget exhaustion annotates remaining findings with "mallcop-budget"
  - CLI pipeline produces valid JSON at each step and persists findings.jsonl
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

_PUBLIC_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.96.0.1", 0))]

import pytest
import yaml
from click.testing import CliRunner

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import (
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    build_actor_runner,
)
from mallcop.cli import cli
from mallcop.escalate import run_escalate
from mallcop.schemas import Annotation, Checkpoint, Event, Finding, FindingStatus, PollResult, Severity
from mallcop.store import JsonlStore


# --- Helpers ---


def _actor_dirs() -> list[Path]:
    """Return real actor directories for triage, investigate, notify_teams."""
    actors_dir = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors"
    return [actors_dir / "triage", actors_dir / "investigate", actors_dir / "notify_teams"]


def _make_config_yaml(
    root: Path,
    budget_overrides: dict[str, Any] | None = None,
    webhook_url: str = "https://teams.example.com/webhook",
) -> None:
    """Write mallcop.yaml configured for full chain scenario."""
    budget = {
        "max_findings_for_actors": 25,
        "max_tokens_per_run": 50000,
        "max_tokens_per_finding": 10000,
    }
    if budget_overrides:
        budget.update(budget_overrides)

    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": {
            "critical": "triage",
            "warn": "triage",
            "info": None,
        },
        "actor_chain": {
            "triage": {"routes_to": "investigate"},
            "investigate": {"routes_to": "notify-teams"},
        },
        "actors": {
            "notify-teams": {"webhook_url": webhook_url},
        },
        "budget": budget,
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_findings(count: int, severity: Severity = Severity.WARN) -> list[Finding]:
    """Create N open findings with given severity."""
    now = datetime.now(timezone.utc)
    findings = []
    for i in range(count):
        findings.append(Finding(
            id=f"fnd_chain_{severity.value}_{i:03d}",
            timestamp=now - timedelta(minutes=30 - i),
            detector="new-actor",
            event_ids=[f"evt_chain_{i:03d}"],
            title=f"Chain finding {i} ({severity.value})",
            severity=severity,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": f"actor_{i}@example.com"},
        ))
    return findings


class EscalatingLLMClient(LLMClient):
    """Mock LLM that always escalates — used to drive findings through the full chain."""

    def __init__(self) -> None:
        self._call_count = 0

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        self._call_count += 1
        # Extract finding_id from the tool-result message content
        finding_id = "unknown"
        for msg in messages:
            if msg.get("role") == "tool" and msg.get("name") == "get-finding-context":
                try:
                    data = json.loads(msg["content"])
                    finding_id = data.get("id", "unknown")
                except (json.JSONDecodeError, TypeError):
                    pass
                break

        return LLMResponse(
            tool_calls=[],
            resolution=ActorResolution(
                finding_id=finding_id,
                action=ResolutionAction.ESCALATED,
                reason=f"Escalating — suspicious activity detected (call {self._call_count})",
            ),
            tokens_used=200,
        )

    @property
    def call_count(self) -> int:
        return self._call_count


# --- Tests ---


class TestFullChainEscalateToChannel:
    """Seed 2 WARN findings → run_escalate → verify full chain delivery to Teams webhook."""

    def test_full_chain_escalate_to_channel(self, tmp_path: Path) -> None:
        """2 WARN findings flow through triage → investigate → notify-teams webhook."""
        root = tmp_path
        _make_config_yaml(root)
        store = JsonlStore(root)

        findings = _make_findings(2, severity=Severity.WARN)
        store.append_findings(findings)

        llm = EscalatingLLMClient()

        runner = build_actor_runner(
            root=root,
            store=store,
            config=MagicMock(connectors={}, actors={"notify-teams": {"webhook_url": "https://teams.example.com/webhook"}}),
            llm=llm,
            actor_dirs=_actor_dirs(),
        )
        assert runner is not None

        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=_PUBLIC_ADDRINFO), \
             patch("mallcop.actors.notify_base.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            result = run_escalate(root, actor_runner=runner)

        assert result["status"] == "ok"
        # Both findings should be processed
        assert result["findings_processed"] == 2

        # Teams webhook should have been called ONCE with consolidated batch digest
        assert mock_post.call_count == 1

        # Verify webhook URL is correct
        call = mock_post.call_args_list[0]
        posted_url = call[0][0] if call[0] else call[1].get("url")
        assert posted_url == "https://teams.example.com/webhook"

        # Verify payload structure matches Teams message card format
        posted_json = call[1].get("json") or call[0][1]
        assert posted_json["type"] == "message"
        assert "Mallcop" in posted_json["summary"]
        assert isinstance(posted_json["sections"], list)
        # Consolidated digest should include both findings
        assert "2 finding" in posted_json["summary"]

        # LLM was called 4 times: 2 findings x 2 agent actors (triage + investigate)
        assert llm.call_count == 4

        # Verify finding states in fresh store
        fresh_store = JsonlStore(root)
        all_findings = fresh_store.query_findings()
        by_id = {f.id: f for f in all_findings}

        # Both findings should have annotations from the escalation
        for fid in ["fnd_chain_warn_000", "fnd_chain_warn_001"]:
            f = by_id[fid]
            assert len(f.annotations) >= 1
            # The escalate pipeline annotates with the actor_name from routing
            ann_actions = [a.action for a in f.annotations]
            assert "escalated" in ann_actions or "resolved" in ann_actions


class TestAnnotationActorNamesCorrect:
    """Verify annotations carry correct actor names after escalation."""

    def test_annotation_actor_names_correct(self, tmp_path: Path) -> None:
        """After escalation, annotations should have actor='triage' (the routing entry actor)."""
        root = tmp_path
        _make_config_yaml(root)
        store = JsonlStore(root)

        findings = _make_findings(2, severity=Severity.WARN)
        store.append_findings(findings)

        llm = EscalatingLLMClient()

        runner = build_actor_runner(
            root=root,
            store=store,
            config=MagicMock(connectors={}, actors={"notify-teams": {"webhook_url": "https://teams.example.com/webhook"}}),
            llm=llm,
            actor_dirs=_actor_dirs(),
        )
        assert runner is not None

        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=_PUBLIC_ADDRINFO), \
             patch("mallcop.actors.notify_base.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            result = run_escalate(root, actor_runner=runner)

        assert result["status"] == "ok"
        assert result["findings_processed"] == 2

        # Read fresh store to get updated findings with annotations
        fresh_store = JsonlStore(root)
        all_findings = fresh_store.query_findings()
        by_id = {f.id: f for f in all_findings}

        # run_escalate annotates with the entry actor name from routing.
        # For WARN findings, routing maps to "triage".
        # The chain internally walks triage → investigate → notify-teams,
        # and with batch consolidation the channel delivers successfully,
        # so run_escalate's annotation records "resolved".
        for fid in ["fnd_chain_warn_000", "fnd_chain_warn_001"]:
            f = by_id[fid]
            assert len(f.annotations) >= 1
            # The annotation actor should be "triage" — the routing entry actor
            # (run_escalate uses actor_name from the batch grouping)
            ann = f.annotations[0]
            assert ann.actor == "triage", (
                f"Expected actor='triage' but got actor='{ann.actor}' on {fid}"
            )
            assert ann.action == "resolved"


class TestChainWithBudgetExhaustion:
    """Set a low token budget, process 3 findings. First processes normally, later ones get budget annotations."""

    def test_chain_with_budget_exhaustion(self, tmp_path: Path) -> None:
        """Low token budget → first finding processed, later ones get mallcop-budget annotation."""
        root = tmp_path
        # Set very low per-run token budget: the chain uses ~400 tokens per finding
        # (200 for triage + 200 for investigate), so 500 allows ~1 finding.
        _make_config_yaml(root, budget_overrides={
            "max_tokens_per_run": 500,
            "max_tokens_per_finding": 10000,
            "max_findings_for_actors": 25,
        })
        store = JsonlStore(root)

        findings = _make_findings(3, severity=Severity.WARN)
        store.append_findings(findings)

        llm = EscalatingLLMClient()

        runner = build_actor_runner(
            root=root,
            store=store,
            config=MagicMock(connectors={}, actors={"notify-teams": {"webhook_url": "https://teams.example.com/webhook"}}),
            llm=llm,
            actor_dirs=_actor_dirs(),
        )
        assert runner is not None

        with patch("mallcop.actors.notify_base.socket.getaddrinfo", return_value=_PUBLIC_ADDRINFO), \
             patch("mallcop.actors.notify_base.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            result = run_escalate(root, actor_runner=runner)

        assert result["status"] == "ok"
        assert result["budget_exhausted"] is True

        # At least 1 finding should have been processed before budget ran out
        assert result["findings_processed"] >= 1
        # Some findings should have been skipped
        assert result["findings_skipped"] >= 1

        # Verify findings in fresh store
        fresh_store = JsonlStore(root)
        all_findings = fresh_store.query_findings()
        by_id = {f.id: f for f in all_findings}

        # Find findings that got budget-exhausted annotations
        budget_annotated = []
        normally_processed = []
        for fid in ["fnd_chain_warn_000", "fnd_chain_warn_001", "fnd_chain_warn_002"]:
            f = by_id[fid]
            budget_anns = [a for a in f.annotations if a.actor == "mallcop-budget"]
            if budget_anns:
                budget_annotated.append(fid)
                # Verify the budget annotation content
                ann = budget_anns[0]
                assert ann.actor == "mallcop-budget"
                assert "Budget exhausted" in ann.content
                assert ann.action == "escalated"
                assert "budget" in ann.reason.lower()
            elif f.annotations:
                normally_processed.append(fid)

        # At least one finding processed normally, at least one budget-exhausted
        assert len(normally_processed) >= 1, (
            f"Expected at least 1 normally processed finding, got {len(normally_processed)}"
        )
        assert len(budget_annotated) >= 1, (
            f"Expected at least 1 budget-exhausted finding, got {len(budget_annotated)}"
        )


# ---------------------------------------------------------------------------
# CLI pipeline test: scan -> detect -> escalate -> review (CliRunner, in-process)
# ---------------------------------------------------------------------------

def _make_github_config_yaml_pipeline(root: Path) -> None:
    """Write mallcop.yaml for the CLI pipeline test."""
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
        "squelch": 0,
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _seed_github_baseline_pipeline(root: Path) -> datetime:
    """Seed known GitHub actors from 20 days ago so learning mode is off."""
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=20)

    known_events: list[Event] = []
    for i, actor in enumerate(["admin-user", "devops-bot"]):
        for j in range(5):
            ts = base_time + timedelta(hours=i * 6 + j)
            known_events.append(Event(
                id=f"evt_pipe_baseline_{actor.replace('-', '_')}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source="github",
                event_type="push",
                actor=actor,
                action="git.push",
                target="acme-corp/web-app",
                severity=Severity.INFO,
                metadata={"org": "acme-corp"},
                raw={"raw_data": True},
            ))

    store = JsonlStore(root)
    store.append_events(known_events)
    store.update_baseline(known_events)
    return now


def _resolving_actor(finding: Finding, **kwargs: Any) -> RunResult:
    """Mock actor: resolves all findings deterministically."""
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.RESOLVED,
            reason="Mock triage: collaborator_added from known org pattern. Resolved.",
        ),
        tokens_used=300,
        iterations=1,
    )


@pytest.mark.functional
class TestCliFullPipelineTransaction:
    """scan -> detect -> escalate -> review as single in-process CliRunner transaction.

    Exercises the full five-stage pipeline using the CLI interface. Each step
    asserts exit_code == 0, valid JSON output shape, and correct on-disk state.
    The scan step is driven by pre-seeding events (GitHub connector poll is
    mocked at the pipeline level). The escalate step uses a mock LLM actor that
    resolves findings. After review the findings_by_severity dict is present.
    """

    def test_init_scan_detect_escalate_review_single_transaction(
        self, tmp_path: Path
    ) -> None:
        """Full CLI pipeline as single transaction: each step exits 0, shapes match,
        findings.jsonl exists after detect, finding is resolved after escalate."""
        root = tmp_path
        cli_runner = CliRunner()

        # Setup: write config and seed baseline (replaces live init/discover)
        _make_github_config_yaml_pipeline(root)
        now = _seed_github_baseline_pipeline(root)

        # Seed the scan events directly -- simulates what scan+connector would do.
        # This is the "mock connector returns collaborator_added event" step.
        collab_event = Event(
            id="evt_pipe_collab_001",
            timestamp=now - timedelta(hours=1),
            ingested_at=now,
            source="github",
            event_type="collaborator_added",
            actor="admin-user",
            action="repo.add_member",
            target="acme-corp/infra",
            severity=Severity.WARN,
            metadata={
                "org": "acme-corp",
                "action_detail": "repo.add_member",
                "permission_level": "admin",
            },
            raw={"user": "new-contractor", "action": "repo.add_member"},
        )
        new_actor_event = Event(
            id="evt_pipe_new_actor_001",
            timestamp=now - timedelta(minutes=55),
            ingested_at=now,
            source="github",
            event_type="push",
            actor="new-contractor",
            action="git.push",
            target="acme-corp/infra",
            severity=Severity.INFO,
            metadata={"org": "acme-corp"},
            raw={"raw_data": True},
        )

        store_pre = JsonlStore(root)
        store_pre.append_events([collab_event, new_actor_event])
        store_pre.set_checkpoint(Checkpoint(
            connector="github",
            value="cursor-pipe-001",
            updated_at=now,
        ))

        # Step 1: Scan (mock connector poll -- events already seeded above)
        with patch(
            "mallcop.cli._run_scan_pipeline",
            return_value={
                "status": "ok",
                "total_events_ingested": 2,
                "connectors": {
                    "github": {
                        "status": "ok",
                        "events_ingested": 2,
                        "checkpoint": "cursor-pipe-001",
                    }
                },
            },
        ):
            with cli_runner.isolated_filesystem(temp_dir=tmp_path):
                scan_result = cli_runner.invoke(cli, ["scan"])

        assert scan_result.exit_code == 0, (
            f"scan exit {scan_result.exit_code}: {scan_result.output}"
        )
        scan_data = json.loads(scan_result.output)
        assert scan_data["status"] == "ok"
        assert "connectors" in scan_data

        # Step 2: Detect -- priv-escalation fires on collaborator_added+admin
        detect_result = cli_runner.invoke(cli, ["detect", "--dir", str(root)])

        assert detect_result.exit_code == 0, (
            f"detect exit {detect_result.exit_code}: {detect_result.output}"
        )
        detect_data = json.loads(detect_result.output)
        assert detect_data["command"] == "detect"
        assert detect_data["status"] == "ok"
        assert "findings_count" in detect_data
        assert detect_data["findings_count"] >= 1, (
            "Expected at least 1 finding: priv-escalation fires on "
            "collaborator_added+permission_level=admin, or new-actor fires for new-contractor"
        )

        # findings.jsonl must exist on disk after detect
        findings_path = root / ".mallcop" / "findings.jsonl"
        assert findings_path.exists(), "findings.jsonl should exist after detect"
        raw_lines = [
            ln for ln in findings_path.read_text().strip().splitlines() if ln.strip()
        ]
        assert len(raw_lines) >= 1
        first_finding = json.loads(raw_lines[0])
        for key in ("id", "severity", "status", "detector", "timestamp"):
            assert key in first_finding, f"finding missing key: {key}"
        assert first_finding["status"] == "open"

        # Step 3: Escalate -- mock LLM resolves finding
        with patch("mallcop.cli._build_actor_runner", return_value=_resolving_actor):
            escalate_result = cli_runner.invoke(cli, ["escalate", "--dir", str(root)])

        assert escalate_result.exit_code == 0, (
            f"escalate exit {escalate_result.exit_code}: {escalate_result.output}"
        )
        escalate_data = json.loads(escalate_result.output)
        assert escalate_data["status"] == "ok"
        assert "findings_processed" in escalate_data
        assert escalate_data["findings_processed"] >= 1

        # On-disk: at least one finding should be resolved
        store_post = JsonlStore(root)
        post_findings = store_post.query_findings()
        resolved = [f for f in post_findings if f.status == FindingStatus.RESOLVED]
        assert len(resolved) >= 1, (
            f"Expected resolved finding after escalate. "
            f"Statuses: {[(f.id, f.status.value) for f in post_findings]}"
        )
        for f in resolved:
            assert len(f.annotations) >= 1
            assert f.annotations[0].action in ("resolved", "escalated")

        # Step 4: Review -- succeeds and returns expected JSON shape
        review_result = cli_runner.invoke(cli, ["review", "--dir", str(root)])

        assert review_result.exit_code == 0, (
            f"review exit {review_result.exit_code}: {review_result.output}"
        )
        review_data = json.loads(review_result.output)
        assert review_data["command"] == "review"
        assert review_data["status"] == "ok"
        assert "findings_by_severity" in review_data
        assert isinstance(review_data["findings_by_severity"], dict)
        assert "post_md" in review_data
        assert "suggested_commands" in review_data
        assert isinstance(review_data["suggested_commands"], list)
