"""Detector manifest schema and loader."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mallcop.schemas import Severity

_VALID_SEVERITIES = {s.value for s in Severity}


@dataclass
class DetectorManifest:
    name: str
    description: str
    version: str
    sources: str | list[str]
    event_types: str | list[str]
    severity_default: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Detector manifest 'name' must not be empty")
        if self.severity_default not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity_default '{self.severity_default}', "
                f"must be one of {_VALID_SEVERITIES}"
            )


def load_detector_manifest(plugin_dir: Path | str) -> DetectorManifest:
    plugin_dir = Path(plugin_dir)
    manifest_path = plugin_dir / "manifest.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.yaml found in {plugin_dir}")

    with open(manifest_path) as f:
        data = yaml.safe_load(f)

    return DetectorManifest(
        name=data["name"],
        description=data["description"],
        version=data["version"],
        sources=data["sources"],
        event_types=data["event_types"],
        severity_default=data["severity_default"],
    )
