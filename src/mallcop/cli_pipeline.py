"""Pipeline orchestration for scan/detect/escalate.

Extracted from cli.py to reduce god-file size. These functions are the
internal engines behind the scan, detect, and watch CLI commands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mallcop.baseline import retrospective_analysis
from mallcop.config import load_config
from mallcop.plugins import instantiate_connector
from mallcop.secrets import ConfigError, EnvSecretProvider
from mallcop.store import JsonlStore, Store


def run_scan_pipeline(root: Path, store: Store | None = None) -> dict[str, Any]:
    """Run the scan step of the pipeline."""
    from mallcop.app_integration import apply_parsers, get_configured_app_names

    try:
        config = load_config(root)
    except ConfigError as e:
        raise RuntimeError(str(e))

    if store is None:
        store = JsonlStore(root)
    connector_summaries: dict[str, Any] = {}
    total_events = 0
    app_names = get_configured_app_names(config.connectors)

    for name, connector_config in config.connectors.items():
        connector = instantiate_connector(name)
        if connector is None:
            connector_summaries[name] = {
                "status": "error",
                "error": f"Unknown connector: {name}",
                "events_ingested": 0,
            }
            continue

        try:
            provider = EnvSecretProvider()
            connector.authenticate(provider)

            connector.configure(connector_config)

            checkpoint = store.get_checkpoint(name)
            poll_result = connector.poll(checkpoint)

            # Apply parser transforms for container-logs apps with parser.yaml
            events = poll_result.events
            if name == "container-logs" and app_names:
                events = apply_parsers(events, root, app_names)

            if events:
                store.append_events(events)

            store.set_checkpoint(poll_result.checkpoint)

            event_count = len(events)
            total_events += event_count

            connector_summaries[name] = {
                "status": "ok",
                "events_ingested": event_count,
                "checkpoint": poll_result.checkpoint.value,
            }

        except Exception as e:
            connector_summaries[name] = {
                "status": "error",
                "error": str(e),
                "events_ingested": 0,
            }

    return {
        "status": "ok",
        "total_events_ingested": total_events,
        "connectors": connector_summaries,
    }


def run_retrospective_if_transitioning(
    store: Store,
    all_events: list,
    baseline: Any,
    sources: set[str],
    currently_learning: set[str],
) -> None:
    """For each connector that just graduated from learning mode, run retrospective.

    A transition occurs when:
    - The connector was previously in learning mode (checkpoint 'was_active' = "true")
    - The connector is no longer in learning mode
    - The retrospective hasn't already been run ('retrospective_done' != "true")

    After running, sets 'retrospective_done' = "true" so it won't re-run.
    Also persists the current learning mode state for each connector.
    """
    from mallcop.schemas import Checkpoint
    from datetime import datetime, timezone

    for source in sources:
        is_now_learning = source in currently_learning
        was_learning_cp = store.get_checkpoint(f"{source}:learning_mode_was_active")
        was_learning = was_learning_cp is not None and was_learning_cp.value == "true"

        # Update stored learning mode state for next run
        store.set_checkpoint(Checkpoint(
            connector=f"{source}:learning_mode_was_active",
            value="true" if is_now_learning else "false",
            updated_at=datetime.now(timezone.utc),
        ))

        # Transition: was learning, now no longer learning
        if was_learning and not is_now_learning:
            retro_done_cp = store.get_checkpoint(f"{source}:retrospective_done")
            if retro_done_cp is not None and retro_done_cp.value == "true":
                continue  # Already ran retrospective for this connector

            retro_findings = retrospective_analysis(source, all_events, baseline)
            if retro_findings:
                store.append_findings(retro_findings)

            store.set_checkpoint(Checkpoint(
                connector=f"{source}:retrospective_done",
                value="true",
                updated_at=datetime.now(timezone.utc),
            ))


def run_detect_pipeline(root: Path, store: Store | None = None) -> dict[str, Any]:
    """Run the detect step of the pipeline."""
    from mallcop.baseline import is_learning_mode
    from mallcop.config import BaselineConfig
    from mallcop.detect import run_detect

    if store is None:
        store = JsonlStore(root)
    baseline = store.get_baseline()

    # Load baseline config for window_days
    try:
        config = load_config(root)
        window_days: int | None = config.baseline.window_days
        config_connectors: dict[str, Any] | None = config.connectors
    except ConfigError:
        window_days = BaselineConfig().window_days
        config_connectors = None

    all_events = store.query_events(limit=100_000)

    # Run detection against current baseline BEFORE updating it with new events.
    # This ensures new actors are flagged before they're added to the baseline.

    sources = {evt.source for evt in all_events}
    learning: set[str] = set()
    for source in sources:
        source_events = [e for e in all_events if e.source == source]
        if is_learning_mode(source, source_events):
            learning.add(source)

    findings = run_detect(
        all_events, baseline, learning_connectors=learning,
        root=root, config_connectors=config_connectors,
    )

    if findings:
        store.append_findings(findings)

    # Update baseline AFTER detection so new actors are included for next run
    store.update_baseline(all_events, window_days=window_days)
    updated_baseline = store.get_baseline()

    # Learning mode transition: run retrospective analysis for connectors that
    # just graduated from learning mode (was_active=true AND no longer learning).
    run_retrospective_if_transitioning(
        store, all_events, updated_baseline, sources, learning
    )

    # Update actor context from accumulated feedback
    try:
        from mallcop.baseline import update_actor_context
        feedback_records = store.query_feedback()
        if feedback_records:
            actor_baseline = update_actor_context(store.get_baseline(), feedback_records)
            bl_path = root / ".mallcop" / "baseline.json"
            bl_path.parent.mkdir(parents=True, exist_ok=True)
            with open(bl_path, "w") as f:
                json.dump(actor_baseline.to_dict(), f)
    except Exception:
        pass  # Actor context update is non-critical

    summary: dict[str, dict[str, int]] = {}
    for f in findings:
        det = f.detector
        sev = f.severity.value
        if det not in summary:
            summary[det] = {}
        summary[det][sev] = summary[det].get(sev, 0) + 1

    return {
        "status": "ok",
        "findings_count": len(findings),
        "summary": summary,
        "learning_connectors": sorted(learning),
        "baseline": {
            "known_actor_count": len(updated_baseline.known_entities.get("actors", [])),
            "frequency_table_entries": len(updated_baseline.frequency_tables),
            "known_sources": updated_baseline.known_entities.get("sources", []),
        },
    }
