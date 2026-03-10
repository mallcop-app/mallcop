"""Actor tools for querying Vercel events."""

from mallcop.tools import make_query_events_tool

query_events = make_query_events_tool(
    tool_name="vercel.query-events",
    description="Query Vercel deployment and audit events.",
    default_source="vercel",
)
