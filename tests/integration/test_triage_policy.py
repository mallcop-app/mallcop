"""Integration test: triage prompt-based resolution policy.

Verifies that:
1. The runtime does NOT enforce a policy override — triage LLM decisions
   are respected for all detector types
2. The triage POST.md contains evidence-based criteria for each detector
   category, including the credential theft test

The runtime-enforcement model has been replaced with prompt-based guidance.
The triage POST.md now provides per-category RESOLVE/ESCALATE criteria
instead of a hard runtime block.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from mallcop.actors._schema import ActorResolution, ResolutionAction, load_actor_manifest
from mallcop.actors.runtime import (
    ActorRuntime,
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    build_actor_runner,
)
from mallcop.config import load_config
from mallcop.escalate import run_escalate
from mallcop.schemas import Annotation, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore
from mallcop.tools import ToolRegistry, tool


# ─── Helpers ──────────────────────────────────────────────────────


def _make_finding(
    id: str = "fnd_001",
    detector: str = "new-external-access",
    severity: Severity = Severity.WARN,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector=detector,
        event_ids=["evt_001"],
        title=f"Test finding from {detector}",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "cmbaron", "source": "github"},
    )


class AlwaysResolveLLM(LLMClient):
    """Mock LLM that always resolves findings."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self._call_count = 0

    def chat(self, model, system_prompt, messages, tools):
        self._call_count += 1
        self.calls.append({"call": self._call_count, "model": model})
        return LLMResponse(
            tool_calls=[ToolCall(
                name="resolve-finding",
                arguments={
                    "finding_id": "fnd_001",
                    "action": "resolved",
                    "reason": f"Resolved on call {self._call_count}",
                },
            )],
            resolution=None,
            tokens_used=100,
            raw_resolution=None,
        )


class AlwaysEscalateLLM(LLMClient):
    """Mock LLM that always escalates findings."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self._call_count = 0

    def chat(self, model, system_prompt, messages, tools):
        self._call_count += 1
        self.calls.append({"call": self._call_count, "model": model})
        return LLMResponse(
            tool_calls=[ToolCall(
                name="resolve-finding",
                arguments={
                    "finding_id": "fnd_001",
                    "action": "escalated",
                    "reason": f"Escalated on call {self._call_count}",
                },
            )],
            resolution=None,
            tokens_used=100,
            raw_resolution=None,
        )


# ─── Tests: Runtime does NOT enforce policy ────────────────────────


class TestRuntimeNoEnforcement:
    """The runtime respects the LLM's resolution decision for all detector types."""

    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    @pytest.fixture
    def investigate_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"

    @pytest.fixture
    def pipeline(self, triage_dir, investigate_dir, tmp_path):
        """Set up a full pipeline with store, config, and actor runner."""
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {"critical": "triage", "warn": "triage", "info": "triage"},
            "actor_chain": {
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": "notify-teams"},
            },
            "budget": {
                "max_findings_for_actors": 25,
                "max_tokens_per_run": 50000,
                "max_tokens_per_finding": 5000,
            },
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config_data, f)

        config = load_config(tmp_path)
        store = JsonlStore(tmp_path)
        return tmp_path, config, store, triage_dir, investigate_dir

    def test_triage_resolve_accepted_for_behavioral(self, pipeline):
        """When triage resolves a behavioral finding, the runtime accepts it."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = AlwaysResolveLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        finding = _make_finding(detector="new-external-access")
        result = runner(finding, actor_name="triage")

        # Runtime does NOT override — triage's resolve is accepted
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert result.resolution.action == ResolutionAction.RESOLVED
        # Only triage was called — no forced escalation to investigate
        assert llm._call_count == 1

    def test_triage_resolve_accepted_for_unusual_timing(self, pipeline):
        """unusual-timing: triage resolution is accepted by runtime."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = AlwaysResolveLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(_make_finding(detector="unusual-timing"), actor_name="triage")

        assert result.resolution.action == ResolutionAction.RESOLVED
        assert llm._call_count == 1

    def test_triage_escalate_accepted_for_any_detector(self, pipeline):
        """When triage escalates, it reaches investigate regardless of detector."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = AlwaysEscalateLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(_make_finding(detector="priv-escalation", severity=Severity.CRITICAL),
                        actor_name="triage")

        # Triage escalated → passed to investigate → investigate escalated
        assert result.resolution.action == ResolutionAction.ESCALATED
        assert llm._call_count == 2  # triage + investigate

    def test_identity_finding_resolved_at_triage(self, pipeline):
        """new-actor: triage can resolve identity detectors."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = AlwaysResolveLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(_make_finding(detector="new-actor"), actor_name="triage")

        assert result.resolution.action == ResolutionAction.RESOLVED
        assert llm._call_count == 1


# ─── Tests: POST.md prompt content ────────────────────────────────


class TestTriagePromptContent:
    """The triage POST.md contains reasoning framework and hard constraints."""

    @pytest.fixture
    def post_md(self) -> str:
        path = (
            Path(__file__).resolve().parents[2]
            / "src" / "mallcop" / "actors" / "triage" / "POST.md"
        )
        return path.read_text()

    def test_credential_theft_test_present(self, post_md):
        """Credential theft test is present in the prompt."""
        assert "stolen" in post_md.lower() or "credential theft" in post_md.lower()

    def test_privilege_always_escalates(self, post_md):
        """Privilege changes always need audit — hard constraint."""
        lower = post_md.lower()
        assert "privilege" in lower
        assert "audit" in lower or "escalat" in lower

    def test_structural_drift_escalates(self, post_md):
        """Structural drift always escalates — hard constraint."""
        lower = post_md.lower()
        assert "structural" in lower or "drift" in lower or "parser" in lower

    def test_positive_evidence_required(self, post_md):
        """Resolution requires positive evidence, not absence of suspicion."""
        lower = post_md.lower()
        assert "positive evidence" in lower

    def test_prompt_injection_defense(self, post_md):
        """Prompt injection markers and defense instructions present."""
        assert "USER_DATA_BEGIN" in post_md
        assert "USER_DATA_END" in post_md
        assert "UNTRUSTED" in post_md

    def test_uba_signals_referenced(self, post_md):
        """UBA context signals (IP, geo, timing, UA) are referenced."""
        lower = post_md.lower()
        # At least 2 of the 4 UBA dimensions mentioned
        uba_count = sum(1 for s in ["ip", "location", "timing", "user-agent"]
                        if s in lower)
        assert uba_count >= 2

    def test_no_rigid_per_category_rules(self, post_md):
        """POST uses reasoning framework, not per-category if/then rules."""
        # Should NOT have the old decision-tree markers
        assert "RESOLVE if:" not in post_md
        assert "ESCALATE if:" not in post_md


# ─── Tests: Full run_escalate pipeline ──────────────────────────────


class TestTriagePolicyFullPipeline:
    """Test triage through run_escalate() — runtime respects LLM decisions."""

    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    @pytest.fixture
    def investigate_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"

    def test_mixed_findings_triage_resolves_all(self, tmp_path, triage_dir, investigate_dir):
        """With always-resolve LLM, triage resolves all findings in one pass."""
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {"warn": "triage", "info": "triage"},
            "actor_chain": {
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": "notify-teams"},
            },
            "budget": {
                "max_findings_for_actors": 25,
                "max_tokens_per_run": 50000,
                "max_tokens_per_finding": 5000,
            },
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config_data, f)

        store = JsonlStore(tmp_path)

        identity_finding = _make_finding(id="fnd_identity", detector="new-actor")
        behavioral_finding = _make_finding(id="fnd_behavioral", detector="new-external-access")
        store.append_findings([identity_finding, behavioral_finding])

        llm = AlwaysResolveLLM()

        runner = build_actor_runner(
            root=tmp_path, store=store, config=load_config(tmp_path), llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = run_escalate(tmp_path, actor_runner=runner, store=store)

        assert result["findings_processed"] == 2

        findings = store.query_findings()
        identity = next(f for f in findings if f.id == "fnd_identity")
        behavioral = next(f for f in findings if f.id == "fnd_behavioral")

        # Both resolved by triage (no forced escalation)
        assert identity.status == FindingStatus.RESOLVED
        assert behavioral.status == FindingStatus.RESOLVED

        # Two findings, each resolved in 1 LLM call (triage only)
        assert llm._call_count == 2

    def test_triage_escalate_reaches_investigate(self, tmp_path, triage_dir, investigate_dir):
        """When triage escalates, findings flow to investigate."""
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {"warn": "triage", "critical": "triage", "info": "triage"},
            "actor_chain": {
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": "notify-teams"},
            },
            "budget": {
                "max_findings_for_actors": 50,
                "max_tokens_per_run": 500000,
                "max_tokens_per_finding": 5000,
            },
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config_data, f)

        store = JsonlStore(tmp_path)

        detectors = [
            "new-external-access",
            "unusual-timing",
            "unusual-resource-access",
            "volume-anomaly",
            "priv-escalation",
            "auth-failure-burst",
            "injection-probe",
        ]
        findings = []
        for i, det in enumerate(detectors):
            sev = Severity.CRITICAL if det == "priv-escalation" else Severity.WARN
            findings.append(_make_finding(id=f"fnd_{i}", detector=det, severity=sev))
        store.append_findings(findings)

        llm = AlwaysEscalateLLM()

        runner = build_actor_runner(
            root=tmp_path, store=store, config=load_config(tmp_path), llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = run_escalate(tmp_path, actor_runner=runner, store=store)

        # 2 detectors (priv-escalation, injection-probe) are hard-escalated
        # deterministically and skip the actor chain. The remaining 5 go through actors.
        hard_escalated = 2
        actor_processed = len(detectors) - hard_escalated
        assert result["findings_processed"] == actor_processed

        # Only actor-processed findings get LLM calls (triage + investigate = 2 each)
        assert llm._call_count == actor_processed * 2
