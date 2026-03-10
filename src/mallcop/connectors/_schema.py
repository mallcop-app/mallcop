"""Connector manifest schema and loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ConnectorManifest:
    name: str
    description: str
    version: str
    auth: dict[str, Any]
    event_types: list[str]
    discovery: dict[str, Any]
    tools: list[dict[str, Any]]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Connector manifest 'name' must not be empty")
        if not self.event_types:
            raise ValueError("Connector manifest 'event_types' must not be empty")


def load_connector_manifest(plugin_dir: Path | str) -> ConnectorManifest:
    plugin_dir = Path(plugin_dir)
    manifest_path = plugin_dir / "manifest.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.yaml found in {plugin_dir}")

    with open(manifest_path) as f:
        data = yaml.safe_load(f)

    return ConnectorManifest(
        name=data["name"],
        description=data["description"],
        version=data["version"],
        auth=data["auth"],
        event_types=data["event_types"],
        discovery=data["discovery"],
        tools=data.get("tools", []),
    )
