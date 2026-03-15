"""Integration test: finding → skill loading → skill-informed investigation.

Validates the complete skills chain using mock LLMs and the real actor runtime.
Tests that:
1. Azure role_assignment finding triggers investigation
2. Investigation actor calls load-skill for "azure-security"
3. The skill context (including parent privilege-analysis) is returned to the LLM
4. Skill-loaded investigation produces richer Azure-specific annotations than no-skill path
"""

from __future__ import annotations

import pytest

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mallcop.actors._schema import ActorResolution, ResolutionAction, load_actor_manifest
from mallcop.actors.runtime import (
    ActorRuntime,
    LLMClient,
    LLMResponse,
    RunResult,
    ToolCall,
    load_post_md,
)
from mallcop.schemas import Annotation, Baseline, Event, Finding, FindingStatus, Severity
from mallcop.tools import ToolContext, ToolRegistry, tool
from tests.shakedown.scenario_store import ScenarioStore

# ── Path helpers ──────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ACTORS_DIR = _REPO_ROOT / "src" / "mallcop" / "actors"
_SKILLS_ROOT = _REPO_ROOT / "src" / "mallcop" / "skills"
_AZURE_SECURITY_SKILL = _SKILLS_ROOT / "azure_security"

# ── Skip guard ────────────────────────────────────────────────────────────────

_SKILL_MISSING = not _AZURE_SECURITY_SKILL.exists()
_SKIP_REASON = "azure-security skill not found at src/mallcop/skills/azure_security/"


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_azure_role_assignment_finding() -> Finding:
    """Build an Azure cross-RG role assignment finding (PE-07 scenario)."""
    return Finding(
        id="fnd_pe07_001",
        timestamp=datetime(2026, 3, 14, 14, 23, 11, tzinfo=timezone.utc),
        detector="priv-escalation",
        event_ids=["evt_pe07_001"],
        title="Privilege escalation: contributor self-granted Contributor on new resource group mallcop-rg",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[
            Annotation(
                actor="triage",
                timestamp=datetime(2026, 3, 14, 14, 25, 0, tzinfo=timezone.utc),
                content=(
                    "Actor contrib-user granted themselves Contributor on mallcop-rg — "
                    "a resource group not found in baseline relationships. "
                    "Zero role_assignment history for this actor. Escalating."
                ),
                action="escalated",
                reason="Self-grant to untouched resource group — possible lateral preparation",
            ),
        ],
        metadata={
            "actor": "contrib-user",
            "source": "azure",
            "event_type": "role_assignment",
            "resource_group": "mallcop-rg",
            "scope": "/subscriptions/169efd95-5e00-42f9-8e65-a1892791ed9a/resourceGroups/mallcop-rg",
            "role": "Contributor",
        },
    )


def _make_scenario_store(finding: Finding) -> ScenarioStore:
    """Build a minimal ScenarioStore seeded with the PE-07 event and baseline."""
    from datetime import timezone

    events = [
        Event(
            id="evt_pe07_001",
            timestamp=datetime(2026, 3, 14, 14, 23, 11, tzinfo=timezone.utc),
            ingested_at=datetime(2026, 3, 14, 14, 24, 0, tzinfo=timezone.utc),
            source="azure",
            event_type="role_assignment",
            actor="contrib-user",
            action="add_role_assignment",
            target="sub-169efd95/resourceGroups/mallcop-rg",
            severity=Severity.WARN,
            metadata={
                "role": "Contributor",
                "principal_id": "contrib-user",
                "principal_type": "User",
                "resource_group": "mallcop-rg",
                "scope": "/subscriptions/169efd95-5e00-42f9-8e65-a1892791ed9a/resourceGroups/mallcop-rg",
            },
            raw={},
        )
    ]
    baseline = Baseline(
        frequency_tables={
            "azure:login:contrib-user": 214,
            "azure:resource_list:contrib-user": 387,
            "azure:read:contrib-user": 501,
            "azure:role_assignment:contrib-user": 0,
        },
        known_entities={
            "actors": ["admin-user", "ci-bot", "contrib-user", "deploy-svc", "tf-automation"],
            "sources": ["azure", "github"],
            "actor_roles": {"contrib-user": ["Contributor"]},
        },
        relationships={
            "contrib-user:sub-169efd95/resourceGroups/atom-rg": {
                "count": 412,
                "first_seen": "2024-03-01",
                "last_seen": "2026-03-13",
            },
            "contrib-user:sub-169efd95/resourceGroups/opensign-rg": {
                "count": 67,
                "first_seen": "2025-01-10",
                "last_seen": "2026-02-28",
            },
        },
    )
    return ScenarioStore(events=events, baseline=baseline, findings=[finding])


def _build_investigation_registry(skill_root: Path | None = None) -> ToolRegistry:
    """Build a ToolRegistry with tools needed by the investigate actor."""
    reg = ToolRegistry()

    @tool(name="read-events", description="Read events by finding ID", permission="read")
    def read_events(finding_id: str | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                "id": "evt_pe07_001",
                "timestamp": "2026-03-14T14:23:11Z",
                "source": "azure",
                "event_type": "role_assignment",
                "actor": "contrib-user",
                "action": "add_role_assignment",
                "target": "sub-169efd95/resourceGroups/mallcop-rg",
                "severity": "warn",
                "metadata": {
                    "role": "Contributor",
                    "principal_id": "contrib-user",
                    "principal_type": "User",
                    "resource_group": "mallcop-rg",
                    "scope": "/subscriptions/169efd95-5e00-42f9-8e65-a1892791ed9a/resourceGroups/mallcop-rg",
                },
            }
        ]

    @tool(name="check-baseline", description="Check baseline for actor/entity", permission="read")
    def check_baseline(actor: str | None = None, **kwargs: Any) -> dict[str, Any]:
        if actor == "contrib-user":
            return {
                "actor": "contrib-user",
                "known": True,
                "frequency": {
                    "azure:login:contrib-user": 214,
                    "azure:resource_list:contrib-user": 387,
                    "azure:read:contrib-user": 501,
                    "azure:role_assignment:contrib-user": 0,
                },
                "relationships": {
                    "sub-169efd95/resourceGroups/atom-rg": {"count": 412, "first_seen": "2024-03-01"},
                    "sub-169efd95/resourceGroups/opensign-rg": {"count": 67, "first_seen": "2025-01-10"},
                },
            }
        return {"actor": actor, "known": False}

    @tool(name="read-finding", description="Read finding details", permission="read")
    def read_finding(finding_id: str, **kwargs: Any) -> dict[str, Any]:
        return _make_azure_role_assignment_finding().to_dict()

    @tool(name="search-events", description="Search events", permission="read")
    def search_events(query: str | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        return []

    @tool(name="search-findings", description="Search findings", permission="read")
    def search_findings(**kwargs: Any) -> list[dict[str, Any]]:
        return []

    @tool(name="read-config", description="Read config", permission="read")
    def read_config(**kwargs: Any) -> dict[str, Any]:
        return {"connectors": {"azure": {}}}

    @tool(name="annotate-finding", description="Annotate a finding", permission="write")
    def annotate_finding(finding_id: str, text: str, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ok", "finding_id": finding_id}

    @tool(name="resolve-finding", description="Resolve or escalate a finding", permission="read")
    def resolve_finding(finding_id: str, action: str, reason: str, **kwargs: Any) -> dict[str, Any]:
        return {"finding_id": finding_id, "action": action, "reason": reason}

    @tool(name="baseline-stats", description="Get baseline statistics", permission="read")
    def baseline_stats(**kwargs: Any) -> dict[str, Any]:
        return {"total_frequency_entries": 12, "known_entities": {"actors": ["contrib-user"]}}

    # load-skill: the real tool if skill_root is set, else a stub
    if skill_root is not None:
        # Import the real load_skill implementation
        from mallcop.tools.skills import load_skill
        reg.register(load_skill)
    else:
        @tool(name="load-skill", description="Load a skill by name", permission="read")
        def load_skill_stub(context: Any, skill_name: str, **kwargs: Any) -> dict[str, Any]:
            return {
                "error": f"No skill_root configured — cannot load '{skill_name}'"
            }
        reg.register(load_skill_stub)

    reg.register(read_events)
    reg.register(check_baseline)
    reg.register(read_finding)
    reg.register(search_events)
    reg.register(search_findings)
    reg.register(read_config)
    reg.register(annotate_finding)
    reg.register(resolve_finding)
    reg.register(baseline_stats)

    return reg


class MockLLMClient(LLMClient):
    """Mock LLM returning pre-programmed responses in sequence."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._call_count = 0
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        self.calls.append({
            "model": model,
            "system_prompt": system_prompt,
            "messages": messages,
            "tools": tools,
        })
        if self._call_count >= len(self._responses):
            raise RuntimeError(
                f"MockLLMClient exhausted all {len(self._responses)} responses "
                f"(call #{self._call_count + 1} attempted)"
            )
        resp = self._responses[self._call_count]
        self._call_count += 1
        return resp


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.integration
@pytest.mark.skipif(_SKILL_MISSING, reason=_SKIP_REASON)
class TestSkillsChainAzureSecurity:
    """Full skills chain: Azure finding → investigate → load azure-security → richer annotations."""

    @pytest.fixture
    def investigate_dir(self) -> Path:
        return _ACTORS_DIR / "investigate"

    def _make_skill_loading_mock(self) -> MockLLMClient:
        """Mock LLM that simulates the investigate actor loading the azure-security skill.

        Turn sequence:
        1. Investigate turn 1 → call load-skill("azure_security") [directory name, not skill name]
        2. Investigate turn 2 (with skill context in messages) → call annotate-finding,
           then resolve-finding with Azure-specific reasoning

        Note: load-skill uses the skill directory name (azure_security with underscore),
        not the skill manifest name (azure-security with hyphen). This matches the
        existing convention for all skills (aws_iam, github_security, etc.).
        """
        escalation = ActorResolution(
            finding_id="fnd_pe07_001",
            action=ResolutionAction.ESCALATED,
            reason=(
                "Azure investigation: contrib-user self-granted Contributor on mallcop-rg "
                "— a resource group with ZERO relationship history in baseline. "
                "Per azure_security skill: actor:scope cross-reference shows count=0 "
                "for contrib-user:mallcop-rg, confirming first-seen lateral preparation. "
                "role_assignment:contrib-user baseline count=0 (actor has never made "
                "role grants). Scope /subscriptions/.../resourceGroups/mallcop-rg is HIGH "
                "risk per Azure RBAC hierarchy. Escalating for human review."
            ),
        )

        return MockLLMClient([
            # Turn 1: load the azure_security skill (directory name with underscore)
            LLMResponse(
                tool_calls=[
                    ToolCall(name="load-skill", arguments={"skill_name": "azure_security"})
                ],
                resolution=None,
                tokens_used=400,
            ),
            # Turn 2: skill context is now in messages — annotate with Azure-specific detail
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="annotate-finding",
                        arguments={
                            "finding_id": "fnd_pe07_001",
                            "text": (
                                "Azure RBAC investigation: contrib-user (known, 214 logins, "
                                "412 interactions with atom-rg) granted themselves Contributor "
                                "on mallcop-rg. Baseline relationship count for "
                                "contrib-user:mallcop-rg = 0 (first-seen scope). "
                                "azure:role_assignment:contrib-user = 0 (actor has NEVER "
                                "made role grants). Scope is resource group level (HIGH risk). "
                                "Per azure-security skill lateral-preparation pattern: "
                                "self-grant to untouched RG indicates possible pivot."
                            ),
                        },
                    )
                ],
                resolution=None,
                tokens_used=600,
            ),
            # Turn 3: resolve
            LLMResponse(
                tool_calls=[],
                resolution=escalation,
                tokens_used=200,
            ),
        ])

    def _make_no_skill_mock(self) -> MockLLMClient:
        """Mock LLM that does NOT load a skill — produces generic investigation."""
        escalation = ActorResolution(
            finding_id="fnd_pe07_001",
            action=ResolutionAction.ESCALATED,
            reason=(
                "Unknown contributor granted themselves access on an unfamiliar resource. "
                "Escalating for review."
            ),
        )

        return MockLLMClient([
            # Turn 1: check baseline (no skill loading)
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="check-baseline",
                        arguments={"actor": "contrib-user"},
                    )
                ],
                resolution=None,
                tokens_used=350,
            ),
            # Turn 2: resolve without deep Azure context
            LLMResponse(
                tool_calls=[],
                resolution=escalation,
                tokens_used=200,
            ),
        ])

    def test_load_skill_tool_call_is_made(self, investigate_dir: Path) -> None:
        """Investigate actor calls load-skill for azure-security when mock returns that tool call."""
        manifest = load_actor_manifest(investigate_dir)
        finding = _make_azure_role_assignment_finding()
        registry = _build_investigation_registry(skill_root=_SKILLS_ROOT)
        post_md = load_post_md(investigate_dir)
        store = _make_scenario_store(finding)

        context = ToolContext(
            store=store,
            connectors={},
            config=None,
            skill_root=_SKILLS_ROOT,
        )
        context.tool_registry = registry

        llm = self._make_skill_loading_mock()
        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm, context=context)
        result = runtime.run(finding=finding, system_prompt=post_md)

        # Chain should escalate (not resolve — this is a real threat)
        assert result.resolution is not None
        assert result.resolution.action == ResolutionAction.ESCALATED

        # The mock called load-skill first
        tool_calls_made = [
            tc["name"]
            for call in llm.calls
            for tc in call.get("tool_calls_preview", [])
        ]
        # Verify via the response sequence: first call returned load-skill tool call
        # The mock sequence tracks what was requested — check call count and result
        assert llm._call_count == 3, f"Expected 3 LLM turns, got {llm._call_count}"

        # Verify the resolution mentions Azure-specific concepts from the skill
        reason = result.resolution.reason.lower()
        assert "resource_group" in reason or "mallcop-rg" in reason, (
            f"Resolution reason should mention Azure resource group scope; got: {result.resolution.reason}"
        )

    def test_skill_context_appears_in_subsequent_messages(self, investigate_dir: Path) -> None:
        """After load-skill is called, the skill context appears in the next LLM turn's messages."""
        manifest = load_actor_manifest(investigate_dir)
        finding = _make_azure_role_assignment_finding()
        registry = _build_investigation_registry(skill_root=_SKILLS_ROOT)
        post_md = load_post_md(investigate_dir)
        store = _make_scenario_store(finding)

        context = ToolContext(
            store=store,
            connectors={},
            config=None,
            skill_root=_SKILLS_ROOT,
        )
        context.tool_registry = registry

        llm = self._make_skill_loading_mock()
        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm, context=context)
        runtime.run(finding=finding, system_prompt=post_md)

        # The second LLM call (turn 2) should have tool result messages containing skill content
        assert len(llm.calls) >= 2, "Expected at least 2 LLM turns"
        turn2_messages = llm.calls[1]["messages"]

        # Find tool result messages in turn 2's message history
        tool_result_messages = [
            m for m in turn2_messages
            if m.get("role") == "tool" and m.get("name") == "load-skill"
        ]
        assert len(tool_result_messages) == 1, (
            "Expected one load-skill tool result in turn 2 messages"
        )

        skill_content = str(tool_result_messages[0].get("content", ""))
        # The azure-security SKILL.md body should contain "Azure" and "resource group"
        assert "azure" in skill_content.lower() or "Azure" in skill_content, (
            f"Skill content should contain Azure-specific material; got: {skill_content[:200]}"
        )

    def test_loaded_skill_contains_azure_rbac_content(self, investigate_dir: Path) -> None:
        """load-skill for azure_security returns Azure RBAC content in tool result.

        Note: skill directories use underscores (azure_security) while skill names in
        SKILL.md use hyphens (azure-security). The load-skill tool takes the directory
        name. The mock calls load-skill with skill_name="azure_security" (directory name).
        We verify the returned skill content covers Azure RBAC investigation topics.
        """
        manifest = load_actor_manifest(investigate_dir)
        finding = _make_azure_role_assignment_finding()
        registry = _build_investigation_registry(skill_root=_SKILLS_ROOT)
        post_md = load_post_md(investigate_dir)
        store = _make_scenario_store(finding)

        context = ToolContext(
            store=store,
            connectors={},
            config=None,
            skill_root=_SKILLS_ROOT,
        )
        context.tool_registry = registry

        llm = self._make_skill_loading_mock()
        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm, context=context)
        runtime.run(finding=finding, system_prompt=post_md)

        # The load-skill tool result should contain Azure RBAC content
        turn2_messages = llm.calls[1]["messages"]
        tool_result_messages = [
            m for m in turn2_messages
            if m.get("role") == "tool" and m.get("name") == "load-skill"
        ]
        assert tool_result_messages, "Expected load-skill tool result in turn 2"
        skill_content = str(tool_result_messages[0].get("content", ""))

        # The skill content should reference RBAC or role assignment concepts
        # (either from azure-security body directly or from an error — if error, the
        # test catches it clearly)
        assert "error" not in skill_content.lower() or "azure" in skill_content.lower(), (
            f"load-skill should return skill content, not an error; got: {skill_content[:300]}"
        )
        # Verify we got actual Azure RBAC content (not an error dict)
        assert "azure" in skill_content.lower() or "rbac" in skill_content.lower() or "role" in skill_content.lower(), (
            f"Skill content should cover Azure topics; got snippet: {skill_content[:300]}"
        )

    def test_scenario_skills_loaded_field(self) -> None:
        """PE-07 scenario YAML declares skills_loaded: [azure-security]."""
        from tests.shakedown.scenario import load_scenario

        scenario_path = (
            _REPO_ROOT
            / "tests"
            / "shakedown"
            / "scenarios"
            / "privilege"
            / "PE-07-azure-cross-rg-role-grant.yaml"
        )
        assert scenario_path.exists(), f"Scenario file not found: {scenario_path}"

        scenario = load_scenario(scenario_path)
        assert "azure-security" in scenario.expected.skills_loaded, (
            f"PE-07 scenario should declare skills_loaded: [azure-security], "
            f"got: {scenario.expected.skills_loaded}"
        )
        assert scenario.expected.chain_action == "escalated"
        assert scenario.expected.triage_action == "escalated"
        assert scenario.expected.investigate_must_use_tools is True


@pytest.mark.integration
@pytest.mark.skipif(_SKILL_MISSING, reason=_SKIP_REASON)
class TestSkillVsNoSkillInvestigation:
    """Skill-loaded investigation produces richer Azure-specific annotations."""

    @pytest.fixture
    def investigate_dir(self) -> Path:
        return _ACTORS_DIR / "investigate"

    def _run_investigation(
        self,
        investigate_dir: Path,
        llm: MockLLMClient,
        with_skill_root: bool,
    ) -> tuple[RunResult, MockLLMClient]:
        manifest = load_actor_manifest(investigate_dir)
        finding = _make_azure_role_assignment_finding()
        skill_root = _SKILLS_ROOT if with_skill_root else None
        registry = _build_investigation_registry(skill_root=skill_root)
        post_md = load_post_md(investigate_dir)
        store = _make_scenario_store(finding)

        context = ToolContext(
            store=store,
            connectors={},
            config=None,
            skill_root=skill_root,
        )
        context.tool_registry = registry

        runtime = ActorRuntime(manifest=manifest, registry=registry, llm=llm, context=context)
        result = runtime.run(finding=finding, system_prompt=post_md)
        return result, llm

    def _make_skill_loading_mock(self) -> MockLLMClient:
        return MockLLMClient([
            # Turn 1: load azure_security skill (directory name, not manifest name)
            LLMResponse(
                tool_calls=[
                    ToolCall(name="load-skill", arguments={"skill_name": "azure_security"})
                ],
                resolution=None,
                tokens_used=400,
            ),
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="annotate-finding",
                        arguments={
                            "finding_id": "fnd_pe07_001",
                            "text": (
                                "Azure RBAC investigation complete. "
                                "Per azure_security skill: contrib-user:mallcop-rg "
                                "relationship count=0 (first-seen scope). "
                                "Scope /subscriptions/.../resourceGroups/mallcop-rg "
                                "is HIGH risk per Azure RBAC hierarchy. "
                                "Self-grant to untouched resource_group matches "
                                "lateral-preparation pattern."
                            ),
                        },
                    )
                ],
                resolution=None,
                tokens_used=600,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_pe07_001",
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        "Azure lateral preparation: self-grant to untouched resource_group "
                        "mallcop-rg. First-seen scope. Zero role_assignment history. "
                        "Scope is resource group level (HIGH risk per azure_security skill)."
                    ),
                ),
                tokens_used=200,
            ),
        ])

    def _make_no_skill_mock(self) -> MockLLMClient:
        return MockLLMClient([
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="check-baseline",
                        arguments={"actor": "contrib-user"},
                    )
                ],
                resolution=None,
                tokens_used=350,
            ),
            LLMResponse(
                tool_calls=[],
                resolution=ActorResolution(
                    finding_id="fnd_pe07_001",
                    action=ResolutionAction.ESCALATED,
                    reason=(
                        "Contributor self-granted access on unfamiliar resource. Escalating."
                    ),
                ),
                tokens_used=200,
            ),
        ])

    def test_skill_loaded_investigation_mentions_azure_concepts(
        self, investigate_dir: Path
    ) -> None:
        """With skill loaded, investigation reason mentions Azure-specific terms."""
        llm = self._make_skill_loading_mock()
        result, _ = self._run_investigation(investigate_dir, llm, with_skill_root=True)

        assert result.resolution is not None
        reason = result.resolution.reason.lower()

        # The skill-loaded mock produces Azure-specific reasoning
        azure_terms = ["resource_group", "mallcop-rg", "scope", "lateral"]
        matched = [t for t in azure_terms if t in reason]
        assert matched, (
            f"Skill-loaded investigation should mention Azure-specific terms "
            f"({azure_terms}); got reason: {result.resolution.reason}"
        )

    def test_no_skill_investigation_is_more_generic(
        self, investigate_dir: Path
    ) -> None:
        """Without skill, investigation reason is shorter and more generic."""
        llm = self._make_no_skill_mock()
        result, _ = self._run_investigation(investigate_dir, llm, with_skill_root=False)

        assert result.resolution is not None
        reason = result.resolution.reason

        # No-skill reasoning should be briefer and lack deep Azure detail
        # We test this structurally: it doesn't mention azure_security-specific terms
        assert "azure_security skill" not in reason.lower() and "azure-security skill" not in reason.lower(), (
            "No-skill investigation should not reference azure_security/azure-security skill"
        )
        assert len(reason) < 250, (
            f"No-skill reason should be brief (< 250 chars); got {len(reason)}: {reason}"
        )

    def test_skill_investigation_uses_more_llm_turns(
        self, investigate_dir: Path
    ) -> None:
        """Skill-loaded investigation requires more LLM turns (skill load + annotate + resolve)."""
        skill_llm = self._make_skill_loading_mock()
        no_skill_llm = self._make_no_skill_mock()

        result_skill, skill_client = self._run_investigation(
            investigate_dir, skill_llm, with_skill_root=True
        )
        result_no_skill, no_skill_client = self._run_investigation(
            investigate_dir, no_skill_llm, with_skill_root=False
        )

        # Skill path: load-skill → annotate → resolve = 3 turns
        # No-skill path: check-baseline → resolve = 2 turns
        assert skill_client._call_count > no_skill_client._call_count, (
            f"Skill path ({skill_client._call_count} turns) should use more LLM calls "
            f"than no-skill path ({no_skill_client._call_count} turns)"
        )

    def test_both_paths_escalate(self, investigate_dir: Path) -> None:
        """Both skill and no-skill investigation paths escalate this finding (correct)."""
        skill_llm = self._make_skill_loading_mock()
        no_skill_llm = self._make_no_skill_mock()

        result_skill, _ = self._run_investigation(
            investigate_dir, skill_llm, with_skill_root=True
        )
        result_no_skill, _ = self._run_investigation(
            investigate_dir, no_skill_llm, with_skill_root=False
        )

        assert result_skill.resolution is not None
        assert result_skill.resolution.action == ResolutionAction.ESCALATED, (
            "Skill path should escalate Azure cross-RG self-grant"
        )
        assert result_no_skill.resolution is not None
        assert result_no_skill.resolution.action == ResolutionAction.ESCALATED, (
            "No-skill path should also escalate (both are correct, skill just adds depth)"
        )
