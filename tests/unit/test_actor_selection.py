"""Tests for shared actor selection logic."""

from __future__ import annotations

from mallcop.actors.actor_selection import select_entry_actor
from mallcop.config import RouteConfig


class TestSelectEntryActor:
    """Tests for select_entry_actor()."""

    def test_returns_none_when_no_route(self):
        """No route for severity -> None."""
        result = select_entry_actor(
            routing={},
            severity="critical",
        )
        assert result is None

    def test_returns_none_when_route_is_none(self):
        """Route exists but is None -> None."""
        result = select_entry_actor(
            routing={"critical": None},
            severity="critical",
        )
        assert result is None

    def test_returns_entry_actor_from_routing(self):
        """Routing maps severity to actor name."""
        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
        )
        assert result == "triage"

    def test_untriaged_finding_returns_entry_actor(self):
        """Finding without annotation from entry actor -> entry actor."""
        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
            annotations=[],
            actor_chain={"triage": {"routes_to": "investigate"}},
        )
        assert result == "triage"

    def test_triaged_finding_follows_chain(self):
        """Finding with annotation from entry actor -> next actor in chain."""
        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
            annotations=[{"actor": "triage", "content": "looks bad"}],
            actor_chain={"triage": {"routes_to": "investigate"}},
        )
        assert result == "investigate"

    def test_triaged_no_chain_returns_entry_actor(self):
        """Finding triaged but no routes_to -> entry actor."""
        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
            annotations=[{"actor": "triage", "content": "ok"}],
            actor_chain={},
        )
        assert result == "triage"

    def test_triaged_with_missing_next_actor_still_returns_it(self):
        """Even if next actor not in actor_chain, return it (with warning)."""
        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
            annotations=[{"actor": "triage", "content": "ok"}],
            actor_chain={"triage": {"routes_to": "investigate"}},
        )
        assert result == "investigate"

    def test_annotations_from_other_actor_dont_count(self):
        """Annotation from different actor != triaged by entry actor."""
        result = select_entry_actor(
            routing={"warn": "triage"},
            severity="warn",
            annotations=[{"actor": "notify-teams", "content": "sent"}],
            actor_chain={"triage": {"routes_to": "investigate"}},
        )
        assert result == "triage"

    def test_no_annotations_kwarg_defaults_to_untriaged(self):
        """When annotations not provided, treat as untriaged."""
        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
            actor_chain={"triage": {"routes_to": "investigate"}},
        )
        assert result == "triage"

    def test_supports_annotation_objects(self):
        """Annotations can be objects with .actor attribute (Annotation dataclass)."""

        class FakeAnnotation:
            def __init__(self, actor: str):
                self.actor = actor

        result = select_entry_actor(
            routing={"critical": "triage"},
            severity="critical",
            annotations=[FakeAnnotation("triage")],
            actor_chain={"triage": {"routes_to": "investigate"}},
        )
        assert result == "investigate"

    def test_different_severity_levels(self):
        """Each severity looks up its own route."""
        routing = {"critical": "triage", "warn": "notify-teams", "info": None}
        assert select_entry_actor(routing=routing, severity="critical") == "triage"
        assert select_entry_actor(routing=routing, severity="warn") == "notify-teams"
        assert select_entry_actor(routing=routing, severity="info") is None

    def test_route_config_extracts_first_chain_actor(self):
        """RouteConfig objects are supported — entry actor is first in chain."""
        route = RouteConfig(chain=["triage", "investigate"], notify=["slack"])
        result = select_entry_actor(
            routing={"critical": route},
            severity="critical",
        )
        assert result == "triage"

    def test_route_config_empty_chain_returns_none(self):
        """RouteConfig with empty chain -> None."""
        route = RouteConfig(chain=[], notify=["slack"])
        result = select_entry_actor(
            routing={"critical": route},
            severity="critical",
        )
        assert result is None
