"""Actor tools for querying AWS CloudTrail events."""

from __future__ import annotations

from mallcop.tools import make_query_events_tool

query_events = make_query_events_tool(
    tool_name="aws-cloudtrail.query-events",
    description="Query AWS CloudTrail events. Returns recent events with optional filtering.",
    default_source="aws-cloudtrail",
)
