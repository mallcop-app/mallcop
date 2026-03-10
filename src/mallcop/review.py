"""Review command logic: group open findings by severity, select POST.md, generate commands."""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any

from mallcop.actors.actor_selection import _extract_entry_actor, select_entry_actor
from mallcop.config import load_config
from mallcop.schemas import Finding, FindingStatus, Severity, SEVERITY_ORDER
from mallcop.store import JsonlStore

# Severity priority order (highest first) — derived from shared constant
_SEVERITY_ORDER = sorted(Severity, key=SEVERITY_ORDER.get)


def _find_post_md(
    actor_name: str,
    deployment_root: Path,
) -> str | None:
    """Load POST.md for an actor. Checks deployment repo first, falls back to built-in."""
    # Check deployment repo actors/ directory first
    deploy_path = deployment_root / "actors" / actor_name / "POST.md"
    if deploy_path.exists():
        return deploy_path.read_text()

    # Fall back to built-in actor POST.md in the package
    builtin_path = Path(__file__).parent / "actors" / actor_name / "POST.md"
    if builtin_path.exists():
        return builtin_path.read_text()

    # Try with hyphens converted to underscores (directory naming convention)
    alt_name = actor_name.replace("-", "_")
    builtin_path = Path(__file__).parent / "actors" / alt_name / "POST.md"
    if builtin_path.exists():
        return builtin_path.read_text()

    return None


def _select_actor_for_review(
    findings_by_severity: dict[str, list[dict[str, Any]]],
    routing: dict[str, str | None],
    actor_chain: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """Select the actor for the highest-severity group that has routing.

    Considers finding annotation state: if ALL findings in the highest-severity
    group have been annotated by the entry actor (triaged), selects the next
    actor in the chain. If any findings are untriaged, selects the entry actor.
    """
    if actor_chain is None:
        actor_chain = {}

    for severity in _SEVERITY_ORDER:
        sev_key = severity.value
        if sev_key in findings_by_severity and findings_by_severity[sev_key]:
            # Check if ALL findings in this group have been triaged.
            # Use the first finding's annotations to probe; if all are triaged,
            # select_entry_actor will follow the chain. If any untriaged, it
            # returns the entry actor. We need to check ALL findings though.
            group = findings_by_severity[sev_key]

            # First, get the entry actor to know what to check
            entry_actor = _extract_entry_actor(routing.get(sev_key))
            if entry_actor is None:
                return None

            all_triaged = all(
                any(
                    ann.get("actor") == entry_actor
                    for ann in finding.get("annotations", [])
                )
                for finding in group
            )

            # Build synthetic annotations list for select_entry_actor:
            # if all triaged, pass an annotation from entry_actor so it follows chain
            # if not all triaged, pass empty so it returns entry_actor
            annotations = [{"actor": entry_actor}] if all_triaged else []

            return select_entry_actor(
                routing=routing,
                severity=sev_key,
                annotations=annotations,
                actor_chain=actor_chain,
            )
    return None


def _generate_suggested_commands(findings: list[Finding]) -> list[str]:
    """Generate suggested mallcop commands with real finding IDs."""
    commands: list[str] = []
    for f in findings:
        commands.append(f"mallcop investigate {f.id}")
        commands.append(f"mallcop finding {f.id}")
        commands.append(f"mallcop events --finding {f.id}")
        commands.append(f"mallcop annotate {f.id} \"<analysis>\"")
        commands.append(f"mallcop ack {f.id}")
    return commands


def run_review(root: Path) -> dict[str, Any]:
    """Load open findings, group by severity, select POST.md, generate commands.

    Returns a structured dict suitable for JSON output.
    """
    config = load_config(root)
    store = JsonlStore(root)

    # Load only open findings
    open_findings = store.query_findings(status="open")

    if not open_findings:
        return {
            "command": "review",
            "status": "ok",
            "findings_by_severity": {},
            "post_md": None,
            "post_md_source": None,
            "suggested_commands": [],
        }

    # Group by severity, ordered by priority
    findings_by_severity: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    for severity in _SEVERITY_ORDER:
        sev_key = severity.value
        group = [f for f in open_findings if f.severity == severity]
        if group:
            findings_by_severity[sev_key] = [f.to_dict() for f in group]

    # Select POST.md based on highest-severity group's routing and annotation state
    actor_name = _select_actor_for_review(
        findings_by_severity, config.routing, config.actor_chain
    )

    post_md: str | None = None
    post_md_source: str | None = None
    if actor_name is not None:
        post_md = _find_post_md(actor_name, root)
        if post_md is not None:
            post_md_source = actor_name

    # Generate suggested commands
    suggested_commands = _generate_suggested_commands(open_findings)

    return {
        "command": "review",
        "status": "ok",
        "findings_by_severity": dict(findings_by_severity),
        "post_md": post_md,
        "post_md_source": post_md_source,
        "suggested_commands": suggested_commands,
    }
