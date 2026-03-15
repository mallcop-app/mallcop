"""Human-readable output formatters for CLI commands.

Extracted from cli.py to reduce god-file size.
"""

from __future__ import annotations

import json
from typing import Any

import click

from mallcop.schemas import Finding


def print_review_human(result: dict[str, Any]) -> None:
    """Print review output in human-readable format."""
    click.echo("== MALLCOP SECURITY REVIEW ==")
    click.echo()

    if result.get("post_md"):
        click.echo(f"POST: {result['post_md_source']}")
        click.echo("---")
        click.echo(result["post_md"])
        click.echo("---")
        click.echo()

    findings_by_severity = result.get("findings_by_severity", {})
    if not findings_by_severity:
        click.echo("No open findings.")
        return

    for severity, findings in findings_by_severity.items():
        count = len(findings)
        click.echo(f"{severity.upper()} ({count} finding{'s' if count != 1 else ''}):")
        for f in findings:
            click.echo(f"  {f['id']}: {f['title']}")
            for ann in f.get("annotations", []):
                click.echo(f"    {ann['actor']}: \"{ann['content']}\"")
        click.echo()

    cmds = result.get("suggested_commands", [])
    if cmds:
        click.echo("COMMANDS:")
        for cmd in cmds:
            click.echo(f"  {cmd}")


def print_investigate_human(result: dict[str, Any]) -> None:
    """Print investigate output in human-readable format."""
    finding = result.get("finding", {})
    click.echo(f"== INVESTIGATE: {finding.get('id')} ==")
    click.echo(f"Title: {finding.get('title')}")
    click.echo(f"Severity: {finding.get('severity', '').upper()}")
    click.echo(f"Status: {finding.get('status')}")
    click.echo(f"Detector: {finding.get('detector')}")
    click.echo()

    if result.get("post_md"):
        click.echo(f"POST: {result['post_md_source']}")
        click.echo("---")
        click.echo(result["post_md"])
        click.echo("---")
        click.echo()

    events = result.get("events", [])
    if events:
        click.echo(f"Triggering Events ({len(events)}):")
        for e in events:
            click.echo(f"  {e['id']}: {e['actor']} {e['action']} {e['target']} @ {e['timestamp']}")
        click.echo()

    annotations = finding.get("annotations", [])
    if annotations:
        click.echo(f"Annotations ({len(annotations)}):")
        for ann in annotations:
            click.echo(f"  [{ann['actor']}] {ann['content']}")
        click.echo()

    actor_history = result.get("actor_history", {})
    if actor_history:
        click.echo("Actor History:")
        for actor, events_list in actor_history.items():
            click.echo(f"  {actor}: {len(events_list)} events")
        click.echo()

    baseline = result.get("baseline", {})
    actors = baseline.get("actors", {})
    if actors:
        click.echo("Baseline:")
        for actor, profile in actors.items():
            known_str = "KNOWN" if profile.get("known") else "UNKNOWN"
            click.echo(f"  {actor}: {known_str}")


def print_finding_human(fnd: Finding) -> None:
    """Print finding detail in human-readable format."""
    click.echo(f"== FINDING: {fnd.id} ==")
    click.echo(f"Title: {fnd.title}")
    click.echo(f"Severity: {fnd.severity.value.upper()}")
    click.echo(f"Status: {fnd.status.value}")
    click.echo(f"Detector: {fnd.detector}")
    click.echo(f"Timestamp: {fnd.timestamp.isoformat()}")
    click.echo(f"Event IDs: {', '.join(fnd.event_ids)}")
    if fnd.metadata:
        click.echo(f"Metadata: {json.dumps(fnd.metadata)}")
    click.echo()
    if fnd.annotations:
        click.echo(f"Annotations ({len(fnd.annotations)}):")
        for ann in fnd.annotations:
            click.echo(f"  [{ann.timestamp.isoformat()}] {ann.actor}: {ann.content}")
