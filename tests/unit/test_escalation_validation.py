"""Tests for escalation path validation — actor_chain config overrides manifest routes_to."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mallcop.actors._schema import ActorManifest
from mallcop.actors.validation import validate_escalation_paths
from mallcop.config import RouteConfig


def _manifest(name: str, mtype: str = "agent", routes_to: str | None = None, config: dict | None = None) -> ActorManifest:
    return ActorManifest(
        name=name,
        type=mtype,
        description="test",
        version="0.1.0",
        model="sonnet",
        tools=[],
        permissions=[],
        routes_to=routes_to,
        max_iterations=3,
        config=config,
    )


@dataclass
class FakeConfig:
    routing: dict[str, Any] = field(default_factory=dict)
    actor_chain: dict[str, dict[str, Any]] = field(default_factory=dict)


class TestActorChainOverride:
    def test_manifest_routes_to_used_by_default(self) -> None:
        """Without actor_chain override, validation follows manifest routes_to."""
        routing = {"warn": RouteConfig(chain=["triage"], notify=[])}
        manifests = {
            "triage": (_manifest("triage", routes_to="notify-teams"), Path(".")),
        }
        channels = {
            "notify-teams": (_manifest("notify-teams", mtype="channel", config={"webhook_url": "${TEAMS_WEBHOOK_URL}"}), Path(".")),
        }
        config = FakeConfig(actor_chain={})
        errors = validate_escalation_paths(routing, manifests, channels, config)
        # Should fail because TEAMS_WEBHOOK_URL is not set
        assert any("notify-teams" in e for e in errors)

    def test_actor_chain_overrides_manifest_routes_to(self) -> None:
        """actor_chain config routes_to takes precedence over manifest routes_to."""
        routing = {"warn": RouteConfig(chain=["triage"], notify=[])}
        manifests = {
            "triage": (_manifest("triage", routes_to="notify-teams"), Path(".")),
            "investigate": (_manifest("investigate", routes_to="notify-teams"), Path(".")),
        }
        channels = {
            "notify-teams": (_manifest("notify-teams", mtype="channel", config={"webhook_url": "${TEAMS_WEBHOOK_URL}"}), Path(".")),
            "notify-email": (_manifest("notify-email", mtype="channel", config={"smtp_host": "smtp.test.com", "from_addr": "a@b.com", "to_addrs": "c@d.com"}), Path(".")),
        }
        config = FakeConfig(
            actor_chain={
                "triage": {"routes_to": "investigate"},
                "investigate": {"routes_to": "notify-email"},
            }
        )
        errors = validate_escalation_paths(routing, manifests, channels, config)
        # Should NOT mention notify-teams because actor_chain redirects to notify-email
        assert not any("notify-teams" in e for e in errors), f"Unexpected teams error: {errors}"
