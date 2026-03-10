"""Tests for actor chain wiring: triage -> investigate -> notify-teams."""

from __future__ import annotations

from pathlib import Path

import pytest

from mallcop.actors._schema import ActorManifest, load_actor_manifest


ACTORS_DIR = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors"


class TestActorChainWiring:
    """Verify the built-in actor chain: triage -> investigate -> notify-teams."""

    def test_triage_routes_to_investigate(self) -> None:
        """Triage manifest must route to investigate, not notify-teams."""
        manifest = load_actor_manifest(ACTORS_DIR / "triage")
        assert manifest.routes_to == "investigate"

    def test_investigate_routes_to_notify_teams(self) -> None:
        """Investigate manifest must route to notify-teams (terminal notification)."""
        manifest = load_actor_manifest(ACTORS_DIR / "investigate")
        assert manifest.routes_to == "notify-teams"

    def test_full_chain_triage_investigate_notify(self) -> None:
        """The full chain must be triage -> investigate -> notify-teams."""
        triage = load_actor_manifest(ACTORS_DIR / "triage")
        investigate = load_actor_manifest(ACTORS_DIR / "investigate")

        assert triage.routes_to == "investigate"
        assert investigate.routes_to == "notify-teams"
        # notify-teams is a channel actor, no routes_to expected


class TestInvestigateManifest:
    """Validate the investigate actor manifest."""

    def test_manifest_exists(self) -> None:
        assert (ACTORS_DIR / "investigate" / "manifest.yaml").exists()

    def test_manifest_loads(self) -> None:
        manifest = load_actor_manifest(ACTORS_DIR / "investigate")
        assert isinstance(manifest, ActorManifest)

    def test_manifest_name(self) -> None:
        manifest = load_actor_manifest(ACTORS_DIR / "investigate")
        assert manifest.name == "investigate"

    def test_manifest_type_is_agent(self) -> None:
        manifest = load_actor_manifest(ACTORS_DIR / "investigate")
        assert manifest.type == "agent"

    def test_manifest_model_is_sonnet(self) -> None:
        """Investigate uses a stronger model than triage (sonnet vs haiku)."""
        manifest = load_actor_manifest(ACTORS_DIR / "investigate")
        assert manifest.model == "sonnet"
