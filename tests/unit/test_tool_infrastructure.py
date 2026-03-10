"""Tests for tool infrastructure: ToolContext, discovery, context injection.

TDD tests for mallcop-8.2.1.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mallcop.tools import (
    ToolContext,
    ToolRegistry,
    ToolMeta,
    PermissionError,
    ToolNotFoundError,
    tool,
)


class TestToolContext:
    """ToolContext dataclass holds store, connectors, and config."""

    def test_construct_with_mock_dependencies(self) -> None:
        store = MagicMock()
        connectors = {"azure": MagicMock()}
        config = MagicMock()
        ctx = ToolContext(store=store, connectors=connectors, config=config)
        assert ctx.store is store
        assert ctx.connectors is connectors
        assert ctx.config is config

    def test_construct_with_empty_connectors(self) -> None:
        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        assert ctx.connectors == {}


class TestSchemaSkipsContext:
    """@tool decorator schema derivation must skip the context: ToolContext param."""

    def test_schema_skips_context_param(self) -> None:
        @tool(name="test-ctx", description="Test", permission="read")
        def my_tool(context: ToolContext, actor: str, limit: int = 10) -> list:
            return []

        meta: ToolMeta = my_tool._tool_meta
        schema = meta.parameter_schema
        assert "context" not in schema
        assert "actor" in schema
        assert schema["actor"]["type"] == "str"
        assert schema["actor"]["required"] is True
        assert "limit" in schema
        assert schema["limit"]["type"] == "int"
        assert schema["limit"]["default"] == 10

    def test_schema_context_only_tool(self) -> None:
        """Tool with only context param should have empty schema."""

        @tool(name="ctx-only", description="Test", permission="read")
        def ctx_only(context: ToolContext) -> dict:
            return {}

        meta: ToolMeta = ctx_only._tool_meta
        assert meta.parameter_schema == {}

    def test_schema_no_context_still_works(self) -> None:
        """Tool without context param still works (backward compat)."""

        @tool(name="no-ctx", description="Test", permission="read")
        def no_ctx(query: str) -> list:
            return []

        meta: ToolMeta = no_ctx._tool_meta
        assert "query" in meta.parameter_schema


class TestDiscoverTools:
    """discover_tools() scans directories for @tool-decorated functions."""

    def _write_tool_file(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))

    def test_discover_from_directory(self, tmp_path: Path) -> None:
        self._write_tool_file(
            tmp_path / "my_tools.py",
            """\
            from mallcop.tools import tool, ToolContext

            @tool(name="discovered-tool", description="Found me", permission="read")
            def discovered(context: ToolContext, x: int = 5) -> int:
                return x
            """,
        )
        registry = ToolRegistry.discover_tools([tmp_path])
        names = [t["name"] for t in registry.list_tools()]
        assert "discovered-tool" in names

    def test_discover_precedence_first_path_wins(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        self._write_tool_file(
            dir_a / "tools.py",
            """\
            from mallcop.tools import tool

            @tool(name="dup-tool", description="From A", permission="read")
            def dup_a() -> str:
                return "a"
            """,
        )
        self._write_tool_file(
            dir_b / "tools.py",
            """\
            from mallcop.tools import tool

            @tool(name="dup-tool", description="From B", permission="read")
            def dup_b() -> str:
                return "b"
            """,
        )
        registry = ToolRegistry.discover_tools([dir_a, dir_b])
        # First path wins — description should be "From A"
        tool_fn = registry.get_tool("dup-tool")
        assert tool_fn._tool_meta.description == "From A"

    def test_discover_skips_files_without_tools(self, tmp_path: Path) -> None:
        self._write_tool_file(
            tmp_path / "no_tools.py",
            """\
            # Just a regular module
            def helper():
                return 42
            """,
        )
        self._write_tool_file(
            tmp_path / "has_tool.py",
            """\
            from mallcop.tools import tool

            @tool(name="real-tool", description="Real", permission="read")
            def real() -> str:
                return "real"
            """,
        )
        registry = ToolRegistry.discover_tools([tmp_path])
        names = [t["name"] for t in registry.list_tools()]
        assert "real-tool" in names
        assert len(names) == 1

    def test_discover_skips_syntax_errors(self, tmp_path: Path) -> None:
        """Files with syntax errors should be skipped silently."""
        (tmp_path / "broken.py").write_text("def broken(\n")
        self._write_tool_file(
            tmp_path / "good.py",
            """\
            from mallcop.tools import tool

            @tool(name="good-tool", description="Good", permission="read")
            def good() -> str:
                return "good"
            """,
        )
        registry = ToolRegistry.discover_tools([tmp_path])
        names = [t["name"] for t in registry.list_tools()]
        assert "good-tool" in names

    def test_discover_nonexistent_path_skipped(self, tmp_path: Path) -> None:
        """Non-existent paths in the list should be silently skipped."""
        registry = ToolRegistry.discover_tools([tmp_path / "nonexistent"])
        assert registry.list_tools() == []

    def test_discover_multiple_tools_in_one_file(self, tmp_path: Path) -> None:
        self._write_tool_file(
            tmp_path / "multi.py",
            """\
            from mallcop.tools import tool

            @tool(name="tool-alpha", description="Alpha", permission="read")
            def alpha() -> str:
                return "alpha"

            @tool(name="tool-beta", description="Beta", permission="write")
            def beta() -> str:
                return "beta"
            """,
        )
        registry = ToolRegistry.discover_tools([tmp_path])
        names = {t["name"] for t in registry.list_tools()}
        assert names == {"tool-alpha", "tool-beta"}


class TestExecute:
    """registry.execute() injects ToolContext and enforces permissions."""

    def test_execute_injects_context(self) -> None:
        captured = {}

        @tool(name="capture", description="Captures context", permission="read")
        def capture_tool(context: ToolContext, value: str = "default") -> str:
            captured["context"] = context
            captured["value"] = value
            return f"got {value}"

        registry = ToolRegistry()
        registry.register(capture_tool)

        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        result = registry.execute("capture", context=ctx, value="hello")

        assert result == "got hello"
        assert captured["context"] is ctx
        assert captured["value"] == "hello"

    def test_execute_no_context_param_still_works(self) -> None:
        """Tools without context param still callable via execute."""

        @tool(name="simple", description="Simple", permission="read")
        def simple_tool(x: int = 1) -> int:
            return x * 2

        registry = ToolRegistry()
        registry.register(simple_tool)

        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        result = registry.execute("simple", context=ctx, x=5)
        assert result == 10

    def test_execute_tool_not_found(self) -> None:
        registry = ToolRegistry()
        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        with pytest.raises(ToolNotFoundError):
            registry.execute("nonexistent", context=ctx)

    def test_execute_permission_enforcement(self) -> None:
        @tool(name="write-tool", description="Write", permission="write")
        def write_tool(context: ToolContext) -> str:
            return "written"

        registry = ToolRegistry()
        registry.register(write_tool)

        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        with pytest.raises(PermissionError):
            registry.execute(
                "write-tool", context=ctx, max_permission="read"
            )

    def test_execute_permission_allows_when_sufficient(self) -> None:
        @tool(name="write-ok", description="Write", permission="write")
        def write_ok(context: ToolContext) -> str:
            return "ok"

        registry = ToolRegistry()
        registry.register(write_ok)

        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        result = registry.execute(
            "write-ok", context=ctx, max_permission="write"
        )
        assert result == "ok"

    def test_execute_default_max_permission_is_write(self) -> None:
        """Without max_permission, execute should allow write tools."""

        @tool(name="write-default", description="Write", permission="write")
        def write_default(context: ToolContext) -> str:
            return "ok"

        registry = ToolRegistry()
        registry.register(write_default)

        ctx = ToolContext(store=MagicMock(), connectors={}, config=MagicMock())
        result = registry.execute("write-default", context=ctx)
        assert result == "ok"


class TestGetEligibleTools:
    """get_eligible_tools() filters by names and permission."""

    def _make_registry(self) -> ToolRegistry:
        registry = ToolRegistry()

        @tool(name="read-a", description="Read A", permission="read")
        def read_a() -> None:
            pass

        @tool(name="read-b", description="Read B", permission="read")
        def read_b() -> None:
            pass

        @tool(name="write-c", description="Write C", permission="write")
        def write_c() -> None:
            pass

        registry.register(read_a)
        registry.register(read_b)
        registry.register(write_c)
        return registry

    def test_filter_by_names_and_permission(self) -> None:
        registry = self._make_registry()
        eligible = registry.get_eligible_tools(
            names=["read-a", "write-c"], max_permission="write"
        )
        names = {t.name for t in eligible}
        assert names == {"read-a", "write-c"}

    def test_filter_excludes_over_permission(self) -> None:
        registry = self._make_registry()
        eligible = registry.get_eligible_tools(
            names=["read-a", "write-c"], max_permission="read"
        )
        names = {t.name for t in eligible}
        assert names == {"read-a"}
        # write-c excluded, not raised

    def test_names_none_returns_all_eligible(self) -> None:
        registry = self._make_registry()
        eligible = registry.get_eligible_tools(
            names=None, max_permission="read"
        )
        names = {t.name for t in eligible}
        assert names == {"read-a", "read-b"}

    def test_names_none_with_write_returns_all(self) -> None:
        registry = self._make_registry()
        eligible = registry.get_eligible_tools(
            names=None, max_permission="write"
        )
        assert len(eligible) == 3
