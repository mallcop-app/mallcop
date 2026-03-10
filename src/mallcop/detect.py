"""Detect command logic: run detectors against events and baseline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mallcop.plugins import discover_plugins, get_search_paths, load_plugin_class
from mallcop.schemas import Baseline, Event, Finding, Severity


def _get_detectors() -> list:
    """Discover and return all detector instances."""
    search_paths = get_search_paths()
    plugins = discover_plugins(search_paths)
    detectors = []
    for _name, info in plugins["detectors"].items():
        cls = load_plugin_class(info)
        if cls is not None:
            detectors.append(cls())
    return detectors


def run_detect(
    events: list[Event],
    baseline: Baseline,
    learning_connectors: set[str],
    *,
    root: Path | None = None,
    config_connectors: dict[str, dict[str, Any]] | None = None,
) -> list[Finding]:
    """Run all detectors against events, applying learning mode.

    Args:
        events: Events to analyze.
        baseline: Current baseline for comparison.
        learning_connectors: Set of connector names still in learning mode.
        root: Deployment root directory (for loading app detectors).
        config_connectors: Connector config dict (for extracting app names).

    Returns:
        List of findings from all detectors.
    """
    from mallcop.app_integration import get_configured_app_names, load_app_detectors

    detectors = _get_detectors()

    # Load declarative detectors from apps/<name>/detectors.yaml
    if root is not None and config_connectors is not None:
        app_names = get_configured_app_names(config_connectors)
        detectors.extend(load_app_detectors(root, app_names))
    all_findings: list[Finding] = []

    for detector in detectors:
        # Filter events by detector's relevant sources/types
        filtered = events
        sources = detector.relevant_sources()
        if sources is not None:
            filtered = [e for e in filtered if e.source in sources]
        event_types = detector.relevant_event_types()
        if event_types is not None:
            filtered = [e for e in filtered if e.event_type in event_types]

        findings = detector.detect(filtered, baseline)

        # Apply learning mode: force severity to INFO for learning connectors
        for finding in findings:
            # Check if any of the finding's source events are from learning connectors
            finding_sources = {
                e.source for e in events if e.id in finding.event_ids
            }
            if finding_sources & learning_connectors:
                finding.severity = Severity.INFO

        all_findings.extend(findings)

    return all_findings
