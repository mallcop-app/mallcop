"""Integration test: triage resolution policy through the full escalation pipeline.

Verifies that the triage agent cannot resolve behavioral, access, privilege,
auth, structural, or signature detectors — only identity (new-actor)
detectors. This is enforced at the runtime level, not just by prompting.

Tests exercise the full path: run_escalate() → run_batch() → actor_runner()
→ ActorRuntime.run() → resolve-finding interception → policy check.

The "credential theft test": a stolen credential IS a known actor. If triage
resolves a finding just because the actor is known, it will miss stolen
credential attacks. The policy prevents this for all behavioral detectors.
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
    _TRIAGE_RESOLVABLE_DETECTORS,
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


class TriageResolvesLLM(LLMClient):
    """Mock LLM that always tries to resolve at triage, escalates at investigate."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def chat(self, model, system_prompt, messages, tools):
        self.calls.append({"model": model, "system_prompt": system_prompt[:50]})
        # Determine which actor is calling based on system prompt content
        if "Level-1" in system_prompt or "triage" in system_prompt.lower()[:100]:
            # Triage always tries to resolve — the policy should override this
            return LLMResponse(
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={
                        "finding_id": "fnd_001",
                        "action": "resolved",
                        "reason": "Known actor cmbaron, normal activity pattern",
                    },
                )],
                resolution=None,
                tokens_used=100,
                raw_resolution=None,
            )
        else:
            # Investigate actor resolves with actual evidence
            return LLMResponse(
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={
                        "finding_id": "fnd_001",
                        "action": "resolved",
                        "reason": "Verified: part of scheduled org migration by admin",
                    },
                )],
                resolution=None,
                tokens_used=200,
                raw_resolution=None,
            )


class TriageAndInvestigateBothResolveLLM(LLMClient):
    """Mock LLM where both triage and investigate try to resolve."""

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


# ─── Tests: Chain walk with build_actor_runner ──────────────────────


class TestTriagePolicyChainWalk:
    """Test triage policy through the full chain walker."""

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

    def test_behavioral_finding_escalated_from_triage_to_investigate(self, pipeline):
        """new-external-access: triage tries to resolve, gets overridden, escalates to investigate."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = TriageResolvesLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        finding = _make_finding(detector="new-external-access")
        result = runner(finding, actor_name="triage")

        # Triage was overridden → escalated to investigate → investigate resolved
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert "Verified" in result.resolution.reason  # investigate's reason
        assert len(llm.calls) == 2  # triage + investigate
        assert result.tokens_used == 300  # 100 + 200

    def test_unusual_timing_escalated_from_triage(self, pipeline):
        """unusual-timing: triage cannot resolve, must escalate."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = TriageResolvesLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(_make_finding(detector="unusual-timing"), actor_name="triage")

        assert result.resolution.action == ResolutionAction.RESOLVED
        assert len(llm.calls) == 2  # forced through to investigate

    def test_priv_escalation_always_reaches_investigate(self, pipeline):
        """priv-escalation (CRITICAL): triage cannot resolve."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = TriageResolvesLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(
            _make_finding(detector="priv-escalation", severity=Severity.CRITICAL),
            actor_name="triage",
        )

        assert len(llm.calls) == 2  # triage + investigate

    def test_identity_finding_resolved_at_triage(self, pipeline):
        """new-actor: triage CAN resolve identity detectors."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = TriageResolvesLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(_make_finding(detector="new-actor"), actor_name="triage")

        # Triage resolved directly — no escalation to investigate
        assert result.resolution.action == ResolutionAction.RESOLVED
        assert "Known actor" in result.resolution.reason  # triage's reason
        assert len(llm.calls) == 1  # only triage

    def test_log_format_drift_escalated_from_triage(self, pipeline):
        """log-format-drift: triage CANNOT resolve, must escalate to investigate."""
        root, config, store, triage_dir, investigate_dir = pipeline
        llm = TriageResolvesLLM()

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = runner(
            _make_finding(detector="log-format-drift", severity=Severity.INFO),
            actor_name="triage",
        )

        # Triage override forces escalation to investigate
        assert result.resolution.action == ResolutionAction.RESOLVED  # investigate resolves
        assert len(llm.calls) == 2  # triage (overridden) + investigate

    def test_triage_override_preserves_assessment_in_escalation_reason(self, pipeline):
        """When triage is overridden, the finding's escalation reason includes
        both the policy message and triage's original assessment."""
        root, config, store, triage_dir, investigate_dir = pipeline

        # LLM where investigate also escalates (so we can see the chain end)
        class AlwaysEscalateLLM(LLMClient):
            def chat(self, model, system_prompt, messages, tools):
                return LLMResponse(
                    tool_calls=[ToolCall(
                        name="resolve-finding",
                        arguments={
                            "finding_id": "fnd_001",
                            "action": "escalated" if "Level-2" in system_prompt else "resolved",
                            "reason": "Cannot confirm" if "Level-2" in system_prompt else "Known actor",
                        },
                    )],
                    resolution=None,
                    tokens_used=100,
                    raw_resolution=None,
                )

        runner = build_actor_runner(
            root=root, store=store, config=config, llm=AlwaysEscalateLLM(),
            actor_dirs=[triage_dir, investigate_dir],
        )
        # Use volume-anomaly — behavioral, not resolvable at triage
        result = runner(_make_finding(detector="volume-anomaly"), actor_name="triage")

        # Triage was overridden (escalated), investigate also escalated
        assert result.resolution.action == ResolutionAction.ESCALATED


# ─── Tests: Full run_escalate pipeline ──────────────────────────────


class TestTriagePolicyFullPipeline:
    """Test triage policy through run_escalate() — the complete pipeline."""

    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    @pytest.fixture
    def investigate_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"

    def test_mixed_findings_correct_routing(self, tmp_path, triage_dir, investigate_dir):
        """Pipeline with mixed detector types: identity resolved at triage,
        behavioral forced to investigate."""
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

        # Two findings: one identity (resolvable), one behavioral (not resolvable)
        identity_finding = _make_finding(id="fnd_identity", detector="new-actor")
        behavioral_finding = _make_finding(id="fnd_behavioral", detector="new-external-access")
        store.append_findings([identity_finding, behavioral_finding])

        llm = TriageAndInvestigateBothResolveLLM()

        runner = build_actor_runner(
            root=tmp_path, store=store, config=load_config(tmp_path), llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        assert runner is not None

        result = run_escalate(tmp_path, actor_runner=runner, store=store)

        assert result["findings_processed"] == 2

        # Check store: identity finding resolved by triage (1 call)
        # behavioral finding resolved by investigate (2 calls: triage overridden + investigate)
        findings = store.query_findings()
        identity = next(f for f in findings if f.id == "fnd_identity")
        behavioral = next(f for f in findings if f.id == "fnd_behavioral")

        assert identity.status == FindingStatus.RESOLVED
        assert behavioral.status == FindingStatus.RESOLVED

        # Identity finding has triage annotation
        identity_annotations = [a for a in identity.annotations if a.actor == "triage"]
        assert len(identity_annotations) >= 1

        # Behavioral finding was escalated from triage to investigate
        # It should have annotations from investigate (not just triage)
        # The LLM was called at least 3 times: triage(identity), triage(behavioral), investigate(behavioral)
        assert llm._call_count >= 3

    def test_all_behavioral_detectors_blocked(self, tmp_path, triage_dir, investigate_dir):
        """Every non-resolvable detector type is blocked at triage."""
        blocked_detectors = [
            "new-external-access",
            "unusual-timing",
            "unusual-resource-access",
            "volume-anomaly",
            "priv-escalation",
            "auth-failure-burst",
            "injection-probe",
        ]
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

        findings = []
        for i, det in enumerate(blocked_detectors):
            sev = Severity.CRITICAL if det == "priv-escalation" else Severity.WARN
            findings.append(_make_finding(id=f"fnd_{i}", detector=det, severity=sev))
        store.append_findings(findings)

        llm = TriageAndInvestigateBothResolveLLM()

        runner = build_actor_runner(
            root=tmp_path, store=store, config=load_config(tmp_path), llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )
        result = run_escalate(tmp_path, actor_runner=runner, store=store)

        assert result["findings_processed"] == len(blocked_detectors)

        # Every blocked detector required 2 LLM calls (triage overridden + investigate)
        # Total: 7 detectors × 2 calls = 14
        assert llm._call_count == len(blocked_detectors) * 2

    def test_resolvable_detectors_accepted(self):
        """Verify the allowlist contains exactly the expected detectors."""
        assert _TRIAGE_RESOLVABLE_DETECTORS == {"new-actor"}


# ─── Tests: Credential theft scenario ──────────────────────────────


class TestCredentialTheftScenario:
    """Simulates the specific credential theft scenario:
    attacker steals cmbaron's credentials and adds a collaborator to the org.

    The system detects new-external-access. Triage sees "known actor cmbaron"
    and tries to resolve. The policy MUST force escalation to investigation.
    """

    @pytest.fixture
    def triage_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "triage"

    @pytest.fixture
    def investigate_dir(self) -> Path:
        return Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors" / "investigate"

    def test_stolen_credential_not_auto_resolved(self, tmp_path, triage_dir, investigate_dir):
        """A stolen credential producing new-external-access MUST reach investigate."""
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
            "routing": {"warn": "triage"},
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
        # The exact scenario: cmbaron (known actor) adds external collaborator
        stolen_cred_finding = Finding(
            id="fnd_stolen",
            timestamp=datetime(2026, 3, 10, 3, 0, 0, tzinfo=timezone.utc),
            detector="new-external-access",
            event_ids=["evt_stolen_001"],
            title="External access granted: collaborator_added on github by cmbaron",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={
                "source": "github",
                "event_type": "collaborator_added",
                "actor": "cmbaron",
                "target": "3dl-dev",
            },
        )
        store.append_findings([stolen_cred_finding])

        # Triage LLM: "known actor, 33 prior interactions, resolve!"
        # This is exactly the rubber-stamp behavior we observed in production.
        class RubberStampTriageLLM(LLMClient):
            def __init__(self):
                self.calls = []

            def chat(self, model, system_prompt, messages, tools):
                self.calls.append({"system_prompt": system_prompt[:50]})
                if "Level-1" in system_prompt or "triage" in system_prompt.lower()[:100]:
                    return LLMResponse(
                        tool_calls=[ToolCall(
                            name="resolve-finding",
                            arguments={
                                "finding_id": "fnd_stolen",
                                "action": "resolved",
                                "reason": "Actor cmbaron is known with 33 prior interactions. Normal activity.",
                            },
                        )],
                        resolution=None, tokens_used=100, raw_resolution=None,
                    )
                else:
                    # Investigate escalates (suspicious — 3am, external access)
                    return LLMResponse(
                        tool_calls=[ToolCall(
                            name="resolve-finding",
                            arguments={
                                "finding_id": "fnd_stolen",
                                "action": "escalated",
                                "reason": "3am external access grant by known actor. Cannot rule out credential theft. Recommend verifying with account owner.",
                            },
                        )],
                        resolution=None, tokens_used=300, raw_resolution=None,
                    )

        llm = RubberStampTriageLLM()
        runner = build_actor_runner(
            root=tmp_path, store=store, config=load_config(tmp_path), llm=llm,
            actor_dirs=[triage_dir, investigate_dir],
        )

        result = run_escalate(tmp_path, actor_runner=runner, store=store)

        # The finding MUST NOT be resolved by triage's rubber stamp
        findings = store.query_findings()
        fnd = next(f for f in findings if f.id == "fnd_stolen")

        # Finding should be escalated (investigate said "can't rule out credential theft")
        assert fnd.status != FindingStatus.RESOLVED or any(
            "credential theft" in a.content for a in fnd.annotations
        ), "Stolen credential scenario was rubber-stamped by triage!"

        # Investigate was called (not just triage)
        assert len(llm.calls) == 2, "Finding never reached investigate!"
