"""Tests for validate_escalation_paths — startup self-validation of actor chains."""

from __future__ import annotations

from pathlib import Path

import pytest

from mallcop.actors._schema import ActorManifest
from mallcop.actors.runtime import (
    EscalationPathError,
    validate_escalation_paths,
    build_actor_runner,
)


def _manifest(
    name: str,
    type: str = "agent",
    routes_to: str | None = None,
    model: str | None = "sonnet",
    config: dict | None = None,
) -> ActorManifest:
    return ActorManifest(
        name=name,
        type=type,
        description=f"{name} actor",
        version="0.1.0",
        model=model if type == "agent" else None,
        tools=[],
        permissions=["read"],
        routes_to=routes_to,
        max_iterations=3 if type == "agent" else None,
        config=config or {},
    )


class TestValidateEscalationPaths:
    def test_valid_chain_with_webhook(self) -> None:
        """Happy path: triage → investigate → notify-teams (webhook configured)."""
        manifests = {
            "triage": (_manifest("triage", routes_to="investigate"), Path(".")),
            "investigate": (_manifest("investigate", routes_to="notify-teams"), Path(".")),
        }
        channels = {
            "notify-teams": (
                _manifest("notify-teams", type="channel", config={"webhook_url": "https://example.com/hook"}),
                Path("."),
            ),
        }
        routing = {"critical": "triage", "warn": "triage"}
        errors = validate_escalation_paths(routing, manifests, channels)
        assert errors == []

    def test_unset_webhook_url(self) -> None:
        """Channel with ${TEAMS_WEBHOOK_URL} is flagged as not configured."""
        manifests = {
            "triage": (_manifest("triage", routes_to="notify-teams"), Path(".")),
        }
        channels = {
            "notify-teams": (
                _manifest("notify-teams", type="channel", config={"webhook_url": "${TEAMS_WEBHOOK_URL}"}),
                Path("."),
            ),
        }
        routing = {"critical": "triage"}
        errors = validate_escalation_paths(routing, manifests, channels)
        assert len(errors) == 1
        assert "webhook_url not configured" in errors[0]

    def test_webhook_override_from_config(self) -> None:
        """Config-level actors.notify-teams.webhook_url overrides manifest default."""
        manifests = {
            "triage": (_manifest("triage", routes_to="notify-teams"), Path(".")),
        }
        channels = {
            "notify-teams": (
                _manifest("notify-teams", type="channel", config={"webhook_url": "${TEAMS_WEBHOOK_URL}"}),
                Path("."),
            ),
        }
        routing = {"critical": "triage"}

        class FakeConfig:
            actors = {"notify-teams": {"webhook_url": "https://real.webhook.com/hook"}}

        errors = validate_escalation_paths(routing, manifests, channels, config=FakeConfig())
        assert errors == []

    def test_missing_actor_in_chain(self) -> None:
        """Chain references actor that doesn't exist."""
        manifests = {
            "triage": (_manifest("triage", routes_to="investigate"), Path(".")),
        }
        channels = {}
        routing = {"warn": "triage"}
        errors = validate_escalation_paths(routing, manifests, channels)
        assert len(errors) == 1
        assert "not found" in errors[0]

    def test_cycle_detection(self) -> None:
        """Cycle in actor chain is flagged."""
        manifests = {
            "a": (_manifest("a", routes_to="b"), Path(".")),
            "b": (_manifest("b", routes_to="a"), Path(".")),
        }
        channels = {}
        routing = {"warn": "a"}
        errors = validate_escalation_paths(routing, manifests, channels)
        assert len(errors) == 1
        assert "cycle" in errors[0]

    def test_chain_ends_without_channel(self) -> None:
        """Chain ends at an agent actor (no routes_to, no channel)."""
        manifests = {
            "triage": (_manifest("triage", routes_to=None), Path(".")),
        }
        channels = {}
        routing = {"warn": "triage"}
        errors = validate_escalation_paths(routing, manifests, channels)
        assert len(errors) == 1
        assert "without reaching a channel" in errors[0]

    def test_null_routing_skipped(self) -> None:
        """Severity routed to None (info: null) is not validated."""
        errors = validate_escalation_paths({"info": None}, {}, {})
        assert errors == []

    def test_invalid_webhook_url(self) -> None:
        """Non-HTTP webhook URL is flagged."""
        manifests = {
            "triage": (_manifest("triage", routes_to="notify-teams"), Path(".")),
        }
        channels = {
            "notify-teams": (
                _manifest("notify-teams", type="channel", config={"webhook_url": "ftp://bad"}),
                Path("."),
            ),
        }
        routing = {"critical": "triage"}
        errors = validate_escalation_paths(routing, manifests, channels)
        assert len(errors) == 1
        assert "not a valid URL" in errors[0]


class TestBuildActorRunnerValidation:
    @pytest.fixture
    def actor_dirs(self) -> list[Path]:
        actors = Path(__file__).resolve().parents[2] / "src" / "mallcop" / "actors"
        return [actors / "triage", actors / "investigate", actors / "notify_teams"]

    def test_validate_paths_true_raises_on_broken_chain(self, tmp_path: Path, actor_dirs: list[Path]) -> None:
        """build_actor_runner with validate_paths=True raises EscalationPathError."""
        import yaml

        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {"warn": "triage"},
            "actor_chain": {"triage": {"routes_to": "notify-teams"}},
            "budget": {},
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config_data, f)

        from mallcop.config import load_config
        from mallcop.store import JsonlStore

        config = load_config(tmp_path)
        store = JsonlStore(tmp_path)

        with pytest.raises(EscalationPathError, match="validation failed"):
            build_actor_runner(
                root=tmp_path,
                store=store,
                config=config,
                llm=None,
                actor_dirs=actor_dirs,
                validate_paths=True,
            )

    def test_validate_paths_false_allows_broken_chain(self, tmp_path: Path, actor_dirs: list[Path]) -> None:
        """build_actor_runner with validate_paths=False does not raise."""
        import yaml

        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {"warn": "triage"},
            "actor_chain": {"triage": {"routes_to": "notify-teams"}},
            "budget": {},
        }
        with open(tmp_path / "mallcop.yaml", "w") as f:
            yaml.dump(config_data, f)

        from mallcop.config import load_config
        from mallcop.store import JsonlStore

        config = load_config(tmp_path)
        store = JsonlStore(tmp_path)

        # Should not raise (returns None because llm=None, but no EscalationPathError)
        runner = build_actor_runner(
            root=tmp_path,
            store=store,
            config=config,
            llm=None,
            actor_dirs=actor_dirs,
            validate_paths=False,
        )
        # Runner is None because llm=None, but the point is no exception was raised
