"""Actor manifest schema and loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

_VALID_ACTOR_TYPES = {"agent", "channel"}


@dataclass
class ActorManifest:
    name: str
    type: str
    description: str
    version: str
    model: str | None
    tools: list[str]
    permissions: list[str]
    routes_to: str | None
    max_iterations: int | None
    config: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Actor manifest 'name' must not be empty")
        if self.type not in _VALID_ACTOR_TYPES:
            raise ValueError(
                f"Invalid actor type '{self.type}', must be one of {_VALID_ACTOR_TYPES}"
            )
        if self.type == "agent" and not self.model:
            raise ValueError("Agent-type actors must specify a 'model'")


class ResolutionAction(str, Enum):
    RESOLVED = "resolved"
    ESCALATED = "escalated"


@dataclass
class ActorResolution:
    finding_id: str
    action: ResolutionAction
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "action": self.action.value,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActorResolution:
        return cls(
            finding_id=data["finding_id"],
            action=ResolutionAction(data["action"]),
            reason=data["reason"],
        )


def load_actor_manifest(plugin_dir: Path | str) -> ActorManifest:
    plugin_dir = Path(plugin_dir)
    manifest_path = plugin_dir / "manifest.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.yaml found in {plugin_dir}")

    with open(manifest_path) as f:
        data = yaml.safe_load(f)

    actor_type = data.get("type")
    if not actor_type:
        raise ValueError("Actor manifest must specify 'type'")

    return ActorManifest(
        name=data["name"],
        type=actor_type,
        description=data["description"],
        version=data["version"],
        model=data.get("model"),
        tools=data.get("tools", []),
        permissions=data.get("permissions", []),
        routes_to=data.get("routes_to"),
        max_iterations=data.get("max_iterations"),
        config=data.get("config", {}),
    )
