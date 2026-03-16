"""discover-app: sample container logs, output structured context for session agent."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from mallcop.config import load_config
from mallcop.connectors.container_logs.connector import ContainerLogsConnector, _parse_log_line
from mallcop.secrets import EnvSecretProvider


class DiscoverAppError(Exception):
    """Raised when discover-app cannot complete."""


def _find_app_config(
    config_dir: Path, app_name: str
) -> tuple[dict[str, Any], dict[str, str]]:
    """Find the named app in container-logs connector config.

    Returns (connector_config, app_entry) where app_entry is the
    matching dict from the apps list.

    Raises DiscoverAppError if not found.
    """
    config = load_config(config_dir)

    cl_config = config.connectors.get("container-logs")
    if cl_config is None:
        raise DiscoverAppError(
            "No container-logs connector configured in mallcop.yaml. "
            "Run 'mallcop init' to discover available connectors."
        )

    apps = cl_config.get("apps", [])
    for app in apps:
        if app.get("name") == app_name:
            return cl_config, app

    available = [a.get("name", "?") for a in apps]
    raise DiscoverAppError(
        f"App '{app_name}' not found in container-logs config. "
        f"Available apps: {', '.join(available) if available else '(none)'}"
    )


def _compute_log_stats(lines: list[str]) -> dict[str, Any]:
    """Compute statistics about log lines."""
    total = len(lines)
    with_ts = 0
    without_ts = 0
    earliest: datetime | None = None
    latest: datetime | None = None

    for line in lines:
        ts, _ = _parse_log_line(line)
        if ts is not None:
            with_ts += 1
            if earliest is None or ts < earliest:
                earliest = ts
            if latest is None or ts > latest:
                latest = ts
        else:
            without_ts += 1

    return {
        "total_lines": total,
        "lines_with_timestamp": with_ts,
        "lines_without_timestamp": without_ts,
        "earliest_timestamp": earliest.isoformat() if earliest else None,
        "latest_timestamp": latest.isoformat() if latest else None,
    }


def discover_app_logic(
    app_name: str,
    config_dir: Path,
    lines: int = 100,
    refresh: bool = False,
) -> dict[str, Any]:
    """Core logic for discover-app command.

    Samples recent logs from the named Container App and returns
    structured JSON for session agent consumption.
    """
    cl_config, app_entry = _find_app_config(config_dir, app_name)

    container_name = app_entry.get("container", app_name)

    # Build connector with config
    connector = ContainerLogsConnector(
        subscription_id=cl_config.get("subscription_id", ""),
        resource_group=cl_config.get("resource_group", ""),
        apps=[app_entry],
    )

    # Authenticate
    provider = EnvSecretProvider()
    connector.authenticate(provider)

    # Fetch logs (no checkpoint = recent logs)
    raw_logs = connector._fetch_logs_for_app(app_name, container_name, since=None)

    # Parse into lines
    if raw_logs and raw_logs.strip():
        all_lines = [l for l in raw_logs.strip().split("\n") if l.strip()]
    else:
        all_lines = []

    # Limit to requested number of lines (take the most recent)
    if len(all_lines) > lines:
        sample = all_lines[-lines:]
    else:
        sample = all_lines

    stats = _compute_log_stats(sample)

    return {
        "app_name": app_name,
        "refresh": refresh,
        "sample_lines": sample,
        "log_stats": stats,
        "suggested_output_paths": [
            f"apps/{app_name}/parser.yaml",
            f"apps/{app_name}/detectors.yaml",
            f"apps/{app_name}/discovery.yaml",
        ],
    }
