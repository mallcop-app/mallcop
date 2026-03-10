"""Tests for tool registry, @tool decorator, and permission enforcement."""

import pytest

from mallcop.tools import tool, ToolRegistry, ToolMeta, PermissionError


class TestToolDecorator:
    """@tool decorator registers a function with correct metadata."""

    def test_decorator_registers_function(self) -> None:
        @tool(name="read-events", description="Read events", permission="read")
        def read_events(source: str, limit: int = 100) -> list:
            return []

        assert hasattr(read_events, "_tool_meta")
        meta = read_events._tool_meta
        assert isinstance(meta, ToolMeta)
        assert meta.name == "read-events"
        assert meta.description == "Read events"
        assert meta.permission == "read"

    def test_decorator_preserves_function(self) -> None:
        @tool(name="test-tool", description="Test", permission="read")
        def my_func(x: int) -> int:
            return x * 2

        assert my_func(5) == 10

    def test_schema_derived_from_type_hints(self) -> None:
        @tool(name="search", description="Search events", permission="read")
        def search_events(
            query: str, source: str | None = None, limit: int = 100
        ) -> list:
            return []

        meta = search_events._tool_meta
        schema = meta.parameter_schema
        assert "query" in schema
        assert schema["query"]["type"] == "str"
        assert schema["query"]["required"] is True
        assert "source" in schema
        assert schema["source"]["required"] is False
        assert schema["source"]["default"] is None
        assert "limit" in schema
        assert schema["limit"]["type"] == "int"
        assert schema["limit"]["required"] is False
        assert schema["limit"]["default"] == 100

    def test_schema_no_params(self) -> None:
        @tool(name="noop", description="No-op", permission="read")
        def noop() -> None:
            pass

        meta = noop._tool_meta
        assert meta.parameter_schema == {}

    def test_permission_must_be_valid(self) -> None:
        with pytest.raises(ValueError, match="permission"):

            @tool(name="bad", description="Bad", permission="admin")
            def bad_tool() -> None:
                pass


class TestToolRegistry:
    """Registry stores tools, filters by name and permission."""

    def _make_registry(self) -> ToolRegistry:
        registry = ToolRegistry()

        @tool(name="read-events", description="Read events", permission="read")
        def read_events(source: str) -> list:
            return []

        @tool(name="search-events", description="Search events", permission="read")
        def search_events(query: str) -> list:
            return []

        @tool(name="annotate-finding", description="Annotate finding", permission="write")
        def annotate_finding(finding_id: str, text: str) -> dict:
            return {}

        @tool(name="read-config", description="Read config", permission="read")
        def read_config() -> dict:
            return {}

        registry.register(read_events)
        registry.register(search_events)
        registry.register(annotate_finding)
        registry.register(read_config)
        return registry

    def test_register_and_list(self) -> None:
        registry = self._make_registry()
        all_tools = registry.list_tools()
        assert len(all_tools) == 4

    def test_get_tools_by_name(self) -> None:
        registry = self._make_registry()
        tools = registry.get_tools(
            names=["read-events", "search-events"], max_permission="read"
        )
        assert len(tools) == 2
        names = {t._tool_meta.name for t in tools}
        assert names == {"read-events", "search-events"}

    def test_get_tools_filters_by_permission(self) -> None:
        registry = self._make_registry()
        # Request write tool but max_permission is read -> should raise
        with pytest.raises(PermissionError):
            registry.get_tools(
                names=["annotate-finding"], max_permission="read"
            )

    def test_get_tools_write_permission_allows_read(self) -> None:
        registry = self._make_registry()
        # With write permission, can access both read and write tools
        tools = registry.get_tools(
            names=["read-events", "annotate-finding"], max_permission="write"
        )
        assert len(tools) == 2

    def test_get_tools_unknown_name_raises(self) -> None:
        registry = self._make_registry()
        with pytest.raises(KeyError):
            registry.get_tools(names=["nonexistent"], max_permission="read")

    def test_get_tools_empty_names(self) -> None:
        registry = self._make_registry()
        tools = registry.get_tools(names=[], max_permission="read")
        assert tools == []

    def test_register_duplicate_raises(self) -> None:
        registry = ToolRegistry()

        @tool(name="duplicate", description="First", permission="read")
        def first() -> None:
            pass

        @tool(name="duplicate", description="Second", permission="read")
        def second() -> None:
            pass

        registry.register(first)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(second)

    def test_permission_hierarchy_read_within_read(self) -> None:
        registry = self._make_registry()
        tools = registry.get_tools(names=["read-events"], max_permission="read")
        assert len(tools) == 1

    def test_permission_hierarchy_write_within_write(self) -> None:
        registry = self._make_registry()
        tools = registry.get_tools(
            names=["annotate-finding"], max_permission="write"
        )
        assert len(tools) == 1

    def test_list_tools_returns_metadata(self) -> None:
        registry = self._make_registry()
        tool_list = registry.list_tools()
        for entry in tool_list:
            assert "name" in entry
            assert "description" in entry
            assert "permission" in entry

    def test_get_tool_by_name(self) -> None:
        registry = self._make_registry()
        fn = registry.get_tool("read-events")
        assert fn._tool_meta.name == "read-events"

    def test_get_tool_not_found(self) -> None:
        registry = ToolRegistry()
        with pytest.raises(KeyError):
            registry.get_tool("nonexistent")
