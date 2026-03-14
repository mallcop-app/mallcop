"""Tests for load-skill tool, ToolContext skill fields, sanitization bypass, and pre-pack."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mallcop.actors._schema import ActorManifest, ResolutionAction
from mallcop.actors.runtime import ActorRuntime
from mallcop.llm_types import LLMResponse, ToolCall
from mallcop.schemas import Finding, FindingStatus, Severity
from mallcop.skills._schema import SkillManifest
from mallcop.tools import ToolContext, ToolRegistry, tool


# ─── Fixtures ────────────────────────────────────────────────────────


def _write_skill(
    skill_dir: Path,
    name: str,
    description: str = "A test skill",
    parent: str | None = None,
    tools_file: bool = False,
) -> Path:
    """Write a minimal SKILL.md into skill_dir."""
    skill_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"name: {name}", f"description: {description}"]
    if parent:
        lines.append(f"parent: {parent}")
    if tools_file:
        lines.append("tools: tools.py")
    content = "---\n" + "\n".join(lines) + "\n---\n\n# Context\nThis is the skill context for {name}.\n".format(name=name)
    (skill_dir / "SKILL.md").write_text(content)
    return skill_dir


def _make_tool_context(
    skill_root: Path | None = None,
    store: Any = None,
    config: Any = None,
) -> ToolContext:
    if store is None:
        store = MagicMock()
        store.get_baseline.return_value = MagicMock(
            known_entities={}, frequency_tables={}, relationships={}
        )
    if config is None:
        config = MagicMock()
    ctx = ToolContext(store=store, connectors={}, config=config)
    if skill_root is not None:
        ctx.skill_root = skill_root
    return ctx


def _make_finding(id: str = "fnd_001") -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="test-detector",
        event_ids=[],
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_manifest(
    tools: list[str] | None = None,
    permissions: list[str] | None = None,
    max_iterations: int = 5,
) -> ActorManifest:
    return ActorManifest(
        name="triage",
        type="agent",
        description="Test actor",
        version="0.1.0",
        model="haiku",
        tools=tools or ["load-skill"],
        permissions=permissions or ["read"],
        routes_to=None,
        max_iterations=max_iterations,
        config={},
    )


# ─── Test: load-skill returns context ────────────────────────────────


class TestLoadSkillReturnsContext:
    """load-skill returns the SKILL.md body text in the context field."""

    def test_load_skill_returns_context(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        skill_dir = tmp_path / "my-skill"
        _write_skill(skill_dir, name="my-skill", description="A useful skill")

        ctx = _make_tool_context(skill_root=tmp_path)

        result = load_skill(ctx, skill_name="my-skill")

        assert isinstance(result, dict)
        assert "context" in result
        assert "my-skill" in result["context"]  # body text contains skill name

    def test_load_skill_result_includes_new_tools(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        skill_dir = tmp_path / "simple-skill"
        _write_skill(skill_dir, name="simple-skill")

        ctx = _make_tool_context(skill_root=tmp_path)

        result = load_skill(ctx, skill_name="simple-skill")

        assert "new_tools" in result
        assert isinstance(result["new_tools"], list)

    def test_load_skill_unknown_skill_returns_error(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        ctx = _make_tool_context(skill_root=tmp_path)

        result = load_skill(ctx, skill_name="nonexistent-skill")

        assert "error" in result

    def test_load_skill_no_skill_root_returns_error(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        ctx = _make_tool_context()  # no skill_root

        result = load_skill(ctx, skill_name="any-skill")

        assert "error" in result


# ─── Test: parent chain loading ───────────────────────────────────────


class TestLoadSkillParentChain:
    """Loading a child skill auto-loads parent first."""

    def test_load_child_auto_loads_parent(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        parent_dir = tmp_path / "base-skill"
        _write_skill(parent_dir, name="base-skill", description="Base skill")

        child_dir = tmp_path / "child-skill"
        _write_skill(child_dir, name="child-skill", parent="base-skill")

        ctx = _make_tool_context(skill_root=tmp_path)

        result = load_skill(ctx, skill_name="child-skill")

        # Both parent and child context should be present
        assert "context" in result
        assert "base-skill" in result["context"]
        assert "child-skill" in result["context"]

    def test_load_child_context_contains_parent_then_child(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        parent_dir = tmp_path / "foundation"
        _write_skill(parent_dir, name="foundation", description="Foundation skill")

        child_dir = tmp_path / "derived"
        _write_skill(child_dir, name="derived", parent="foundation")

        ctx = _make_tool_context(skill_root=tmp_path)

        result = load_skill(ctx, skill_name="derived")

        # Parent context comes first in concatenation
        context = result["context"]
        parent_pos = context.find("foundation")
        child_pos = context.find("derived")
        assert parent_pos < child_pos, "Parent context should precede child context"

    def test_parent_also_stored_in_loaded_skills(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        parent_dir = tmp_path / "parent-skill"
        _write_skill(parent_dir, name="parent-skill")

        child_dir = tmp_path / "child-skill"
        _write_skill(child_dir, name="child-skill", parent="parent-skill")

        ctx = _make_tool_context(skill_root=tmp_path)

        load_skill(ctx, skill_name="child-skill")

        # Both parent and child should be in loaded_skills cache
        assert "parent-skill" in ctx.loaded_skills
        assert "child-skill" in ctx.loaded_skills


# ─── Test: idempotent reload ─────────────────────────────────────────


class TestLoadSkillIdempotent:
    """Second call for same skill name returns cached result."""

    def test_second_call_returns_cached(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        skill_dir = tmp_path / "cached-skill"
        _write_skill(skill_dir, name="cached-skill")

        ctx = _make_tool_context(skill_root=tmp_path)

        result1 = load_skill(ctx, skill_name="cached-skill")
        result2 = load_skill(ctx, skill_name="cached-skill")

        assert result1 == result2

    def test_second_call_does_not_re_read_file(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        skill_dir = tmp_path / "idempotent-skill"
        _write_skill(skill_dir, name="idempotent-skill")

        ctx = _make_tool_context(skill_root=tmp_path)

        load_skill(ctx, skill_name="idempotent-skill")

        # Modify SKILL.md after first load
        (skill_dir / "SKILL.md").write_text(
            "---\nname: idempotent-skill\ndescription: Changed\n---\nDifferent content.\n"
        )

        result2 = load_skill(ctx, skill_name="idempotent-skill")

        # Should still have original content (cached)
        assert "Different content" not in result2["context"]

    def test_parent_loaded_only_once_for_multiple_children(self, tmp_path: Path) -> None:
        from mallcop.tools.skills import load_skill

        parent_dir = tmp_path / "shared-parent"
        _write_skill(parent_dir, name="shared-parent")

        child1_dir = tmp_path / "child-one"
        _write_skill(child1_dir, name="child-one", parent="shared-parent")

        child2_dir = tmp_path / "child-two"
        _write_skill(child2_dir, name="child-two", parent="shared-parent")

        ctx = _make_tool_context(skill_root=tmp_path)

        load_skill(ctx, skill_name="child-one")
        load_skill(ctx, skill_name="child-two")

        # Parent should be in cache, loaded only once
        assert "shared-parent" in ctx.loaded_skills


# ─── Test: sanitization bypass ───────────────────────────────────────


class TestSkillContextNotSanitized:
    """load-skill results are NOT wrapped in USER_DATA markers."""

    def _make_mock_llm_with_tool_call(self, tool_name: str, args: dict) -> MagicMock:
        """Build a mock LLM that returns one tool call then resolves."""
        call_count = 0

        def chat_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return LLMResponse(
                    text="",
                    tool_calls=[ToolCall(name=tool_name, arguments=args)],
                    resolution=None,
                    raw_resolution=None,
                    tokens_used=10,
                )
            # Second iteration: resolve
            from mallcop.actors._schema import ActorResolution
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={"finding_id": "fnd_001", "action": "resolved", "reason": "done"},
                )],
                resolution=None,
                raw_resolution=None,
                tokens_used=5,
            )

        mock_llm = MagicMock()
        mock_llm.chat.side_effect = chat_side_effect
        return mock_llm

    def test_load_skill_result_not_wrapped_in_user_data_markers(self, tmp_path: Path) -> None:
        """Verify load-skill tool result is not sanitized with USER_DATA markers."""
        from mallcop.tools.skills import load_skill

        skill_dir = tmp_path / "test-skill"
        _write_skill(skill_dir, name="test-skill")

        ctx = _make_tool_context(skill_root=tmp_path)
        result = load_skill(ctx, skill_name="test-skill")

        # The context field should NOT contain USER_DATA markers
        context_text = result.get("context", "")
        assert "[USER_DATA_BEGIN]" not in context_text
        assert "[USER_DATA_END]" not in context_text

    def test_load_skill_message_in_runtime_not_sanitized(self, tmp_path: Path) -> None:
        """In the actor runtime, load-skill tool results bypass sanitize_tool_result."""
        skill_dir = tmp_path / "bypass-skill"
        _write_skill(skill_dir, name="bypass-skill", description="Bypass test skill")

        store = MagicMock()
        store.get_baseline.return_value = MagicMock(
            known_entities={}, frequency_tables={}, relationships={}
        )
        ctx = _make_tool_context(skill_root=tmp_path, store=store)

        reg = ToolRegistry()
        from mallcop.tools.skills import load_skill as _load_skill_fn
        reg.register(_load_skill_fn)

        # Register resolve-finding tool so runtime can process it
        @tool(name="resolve-finding", description="Resolve", permission="read")
        def resolve_finding(finding_id: str, action: str, reason: str) -> dict:
            return {"finding_id": finding_id, "action": action, "reason": reason}
        reg.register(resolve_finding)

        manifest = _make_manifest(tools=["load-skill", "resolve-finding"])
        mock_llm = self._make_mock_llm_with_tool_call(
            "load-skill", {"skill_name": "bypass-skill"}
        )

        runtime = ActorRuntime(
            manifest=manifest, registry=reg, llm=mock_llm, context=ctx
        )

        finding = _make_finding()
        result = runtime.run(finding=finding, system_prompt="Test")

        # Verify tool was called and result message was appended
        assert mock_llm.chat.call_count >= 1
        # Get the messages passed to second chat call
        second_call_messages = mock_llm.chat.call_args_list[1][1]["messages"]
        tool_msg = next(
            (m for m in second_call_messages if m.get("role") == "tool" and m.get("name") == "load-skill"),
            None,
        )
        assert tool_msg is not None
        content = tool_msg["content"]
        assert "[USER_DATA_BEGIN]" not in content
        assert "[USER_DATA_END]" not in content


# ─── Test: skill catalog pre-packed ──────────────────────────────────


class TestSkillCatalogPrepacked:
    """Skill catalog is pre-packed into actor messages, no list-skills call needed."""

    def test_skill_catalog_appears_in_messages(self, tmp_path: Path) -> None:
        """Pre-packed messages include a skill catalog tool result."""
        skill_a_dir = tmp_path / "skill-alpha"
        _write_skill(skill_a_dir, name="skill-alpha", description="Alpha skill")

        skill_b_dir = tmp_path / "skill-beta"
        _write_skill(skill_b_dir, name="skill-beta", description="Beta skill")

        store = MagicMock()
        store.get_baseline.return_value = MagicMock(
            known_entities={}, frequency_tables={}, relationships={}
        )
        store.query_events.return_value = []

        ctx = _make_tool_context(skill_root=tmp_path, store=store)

        reg = ToolRegistry()

        @tool(name="resolve-finding", description="Resolve", permission="read")
        def resolve_finding_tool(finding_id: str, action: str, reason: str) -> dict:
            return {}
        reg.register(resolve_finding_tool)

        manifest = _make_manifest(tools=["resolve-finding"])

        messages_captured = []

        def capture_chat(**kwargs):
            messages_captured.extend(kwargs.get("messages", []))
            from mallcop.actors._schema import ActorResolution
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={"finding_id": "fnd_001", "action": "resolved", "reason": "done"},
                )],
                resolution=None,
                raw_resolution=None,
                tokens_used=10,
            )

        mock_llm = MagicMock()
        mock_llm.chat.side_effect = capture_chat

        runtime = ActorRuntime(
            manifest=manifest, registry=reg, llm=mock_llm, context=ctx
        )

        finding = _make_finding()
        runtime.run(finding=finding, system_prompt="Test")

        # Skill catalog should appear as a tool result in the initial messages
        catalog_messages = [
            m for m in messages_captured
            if m.get("role") == "tool" and m.get("name") == "list-skills"
        ]
        assert len(catalog_messages) == 1
        content = catalog_messages[0]["content"]
        assert "skill-alpha" in content
        assert "skill-beta" in content

    def test_skill_catalog_includes_name_and_description(self, tmp_path: Path) -> None:
        """Each skill entry in the catalog has name, description, parent, has_tools."""
        skill_dir = tmp_path / "catalog-skill"
        _write_skill(skill_dir, name="catalog-skill", description="Catalog description")

        store = MagicMock()
        store.get_baseline.return_value = MagicMock(
            known_entities={}, frequency_tables={}, relationships={}
        )
        store.query_events.return_value = []

        ctx = _make_tool_context(skill_root=tmp_path, store=store)

        reg = ToolRegistry()

        @tool(name="resolve-finding", description="Resolve", permission="read")
        def resolve_fn(finding_id: str, action: str, reason: str) -> dict:
            return {}
        reg.register(resolve_fn)

        manifest = _make_manifest(tools=["resolve-finding"])

        messages_captured = []

        def capture_and_resolve(**kwargs):
            messages_captured.extend(kwargs.get("messages", []))
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={"finding_id": "fnd_001", "action": "resolved", "reason": "done"},
                )],
                resolution=None,
                raw_resolution=None,
                tokens_used=10,
            )

        mock_llm = MagicMock()
        mock_llm.chat.side_effect = capture_and_resolve

        runtime = ActorRuntime(
            manifest=manifest, registry=reg, llm=mock_llm, context=ctx
        )

        finding = _make_finding()
        runtime.run(finding=finding, system_prompt="Test")

        catalog_msg = next(
            (m for m in messages_captured if m.get("name") == "list-skills"),
            None,
        )
        assert catalog_msg is not None
        content = catalog_msg["content"]
        assert "Catalog description" in content

    def test_no_skill_catalog_when_no_skill_root(self) -> None:
        """When ToolContext has no skill_root, no catalog is pre-packed."""
        store = MagicMock()
        store.get_baseline.return_value = MagicMock(
            known_entities={}, frequency_tables={}, relationships={}
        )
        store.query_events.return_value = []

        ctx = _make_tool_context(store=store)  # no skill_root

        reg = ToolRegistry()

        @tool(name="resolve-finding", description="Resolve", permission="read")
        def resolve_fn2(finding_id: str, action: str, reason: str) -> dict:
            return {}
        reg.register(resolve_fn2)

        manifest = _make_manifest(tools=["resolve-finding"])

        messages_captured = []

        def capture_and_resolve(**kwargs):
            messages_captured.extend(kwargs.get("messages", []))
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    name="resolve-finding",
                    arguments={"finding_id": "fnd_001", "action": "resolved", "reason": "done"},
                )],
                resolution=None,
                raw_resolution=None,
                tokens_used=10,
            )

        mock_llm = MagicMock()
        mock_llm.chat.side_effect = capture_and_resolve

        runtime = ActorRuntime(
            manifest=manifest, registry=reg, llm=mock_llm, context=ctx
        )

        finding = _make_finding()
        runtime.run(finding=finding, system_prompt="Test")

        catalog_messages = [
            m for m in messages_captured if m.get("name") == "list-skills"
        ]
        assert len(catalog_messages) == 0
