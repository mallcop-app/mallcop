"""Tests for make_query_events_tool factory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest


def _make_mock_event(id: str, source: str, actor: str) -> MagicMock:
    evt = MagicMock()
    evt.id = id
    evt.source = source
    evt.actor = actor
    evt.to_dict.return_value = {"id": id, "source": source, "actor": actor}
    return evt


class TestMakeQueryEventsToolImports:
    """Verify that the factory is importable and connector tools resolve."""

    def test_factory_importable(self):
        from mallcop.tools import make_query_events_tool

        assert callable(make_query_events_tool)

    def test_aws_cloudtrail_tools_import(self):
        from mallcop.connectors.aws_cloudtrail.tools import query_events

        assert hasattr(query_events, "_tool_meta")
        assert query_events._tool_meta.name == "aws-cloudtrail.query-events"

    def test_vercel_tools_import(self):
        from mallcop.connectors.vercel.tools import query_events

        assert hasattr(query_events, "_tool_meta")
        assert query_events._tool_meta.name == "vercel.query-events"


class TestMakeQueryEventsToolFactory:
    """Verify that make_query_events_tool produces correct tool functions."""

    def test_creates_tool_with_correct_meta(self):
        from mallcop.tools import make_query_events_tool

        fn = make_query_events_tool(
            tool_name="test.query-events",
            description="Test query tool",
            default_source="test-source",
        )
        assert fn._tool_meta.name == "test.query-events"
        assert fn._tool_meta.description == "Test query tool"
        assert fn._tool_meta.permission == "read"

    def test_uses_default_source_when_none_given(self):
        from mallcop.tools import ToolContext, make_query_events_tool

        fn = make_query_events_tool(
            tool_name="test.query",
            description="desc",
            default_source="my-source",
        )
        mock_store = MagicMock()
        evt = _make_mock_event("e1", "my-source", "alice")
        mock_store.query_events.return_value = [evt]

        ctx = ToolContext(store=mock_store, connectors={}, config=None)
        result = fn(ctx)

        mock_store.query_events.assert_called_once_with(
            source="my-source", actor=None, since=None, limit=100
        )
        assert result == [{"id": "e1", "source": "my-source", "actor": "alice"}]

    def test_allows_source_override(self):
        from mallcop.tools import ToolContext, make_query_events_tool

        fn = make_query_events_tool(
            tool_name="test.query",
            description="desc",
            default_source="default-src",
        )
        mock_store = MagicMock()
        mock_store.query_events.return_value = []

        ctx = ToolContext(store=mock_store, connectors={}, config=None)
        fn(ctx, source="override-src")

        mock_store.query_events.assert_called_once_with(
            source="override-src", actor=None, since=None, limit=100
        )

    def test_passes_actor_and_limit(self):
        from mallcop.tools import ToolContext, make_query_events_tool

        fn = make_query_events_tool(
            tool_name="test.query",
            description="desc",
            default_source="src",
        )
        mock_store = MagicMock()
        mock_store.query_events.return_value = []

        ctx = ToolContext(store=mock_store, connectors={}, config=None)
        fn(ctx, actor="bob", limit=10)

        mock_store.query_events.assert_called_once_with(
            source="src", actor="bob", since=None, limit=10
        )

    def test_parses_since_as_iso_datetime(self):
        from mallcop.tools import ToolContext, make_query_events_tool

        fn = make_query_events_tool(
            tool_name="test.query",
            description="desc",
            default_source="src",
        )
        mock_store = MagicMock()
        mock_store.query_events.return_value = []

        ctx = ToolContext(store=mock_store, connectors={}, config=None)
        fn(ctx, since="2025-01-15T10:30:00+00:00")

        call_kwargs = mock_store.query_events.call_args[1]
        assert call_kwargs["since"] == datetime(2025, 1, 15, 10, 30, tzinfo=timezone.utc)
