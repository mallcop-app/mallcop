"""Finding query and annotation tools for actor runtime."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from mallcop.schemas import Annotation
from mallcop.tools import ToolContext, tool


@tool(name="read-finding", description="Read full finding details", permission="read")
def read_finding(context: ToolContext, finding_id: str) -> dict[str, Any]:
    """Read a finding by ID, returning the full finding dict with annotations.

    Returns error dict if the finding is not found.
    """
    store = context.store
    findings = store.query_findings()
    matching = [f for f in findings if f.id == finding_id]
    if not matching:
        return {"error": f"Finding '{finding_id}' not found"}
    return matching[0].to_dict()


@tool(name="list-findings", description="List findings with optional filters", permission="read")
def list_findings(
    context: ToolContext,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List findings with optional status/severity filters.

    Returns a list of finding summary dicts, truncated to limit.
    """
    store = context.store
    findings = store.query_findings(status=status, severity=severity)
    return [f.to_dict() for f in findings[:limit]]


@tool(name="resolve-finding", description="Resolve or escalate a finding with a reason. action must be 'resolved' or 'escalated'.", permission="read")
def resolve_finding(
    context: ToolContext,
    finding_id: str,
    action: str,
    reason: str,
) -> dict[str, Any]:
    """Submit a resolution decision for a finding.

    This tool signals the runtime to stop processing and apply the resolution.
    action must be 'resolved' (benign/known) or 'escalated' (needs deeper investigation).
    The runtime intercepts this tool call — the return value is not used.
    """
    return {"finding_id": finding_id, "action": action, "reason": reason}


@tool(name="annotate-finding", description="Add annotation to a finding", permission="write")
def annotate_finding(
    context: ToolContext,
    finding_id: str,
    text: str,
    action: str = "annotate",
) -> dict[str, Any]:
    """Add an annotation to a finding and persist via store.update_finding.

    Returns the finding dict, or error dict if not found.
    """
    store = context.store
    findings = store.query_findings()
    matching = [f for f in findings if f.id == finding_id]
    if not matching:
        return {"error": f"Finding '{finding_id}' not found"}

    finding = matching[0]
    ann = Annotation(
        actor=context.actor_name,
        timestamp=datetime.now(timezone.utc),
        content=text,
        action=action,
        reason=None,
    )

    store.update_finding(finding_id, annotations=[ann])
    return finding.to_dict()
