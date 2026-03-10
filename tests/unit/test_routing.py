"""Tests for channel routing redesign — RouteConfig parsing and backward compatibility."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mallcop.config import RouteConfig, _parse_routing, load_config


class TestRouteConfig:
    def test_fields(self) -> None:
        rc = RouteConfig(chain=["triage", "investigate"], notify=["slack"])
        assert rc.chain == ["triage", "investigate"]
        assert rc.notify == ["slack"]

    def test_empty(self) -> None:
        rc = RouteConfig(chain=[], notify=[])
        assert rc.chain == []
        assert rc.notify == []


class TestParseRouting:
    def test_old_format_string(self) -> None:
        raw = {"critical": "triage", "warn": "triage", "info": None}
        result = _parse_routing(raw)
        assert result["critical"].chain == ["triage"]
        assert result["critical"].notify == []
        assert result["info"] is None

    def test_new_format_dict(self) -> None:
        raw = {
            "critical": {"chain": ["triage", "investigate"], "notify": ["slack", "email"]},
            "warn": {"chain": ["triage"], "notify": ["slack"]},
            "info": None,
        }
        result = _parse_routing(raw)
        assert result["critical"].chain == ["triage", "investigate"]
        assert result["critical"].notify == ["slack", "email"]
        assert result["warn"].chain == ["triage"]
        assert result["warn"].notify == ["slack"]
        assert result["info"] is None

    def test_none_routing(self) -> None:
        result = _parse_routing(None)
        assert result == {}

    def test_empty_routing(self) -> None:
        result = _parse_routing({})
        assert result == {}

    def test_mixed_format(self) -> None:
        raw = {
            "critical": {"chain": ["triage"], "notify": ["slack"]},
            "warn": "triage",
        }
        result = _parse_routing(raw)
        assert isinstance(result["critical"], RouteConfig)
        assert result["critical"].chain == ["triage"]
        assert result["critical"].notify == ["slack"]
        assert isinstance(result["warn"], RouteConfig)
        assert result["warn"].chain == ["triage"]
        assert result["warn"].notify == []

    def test_dict_missing_chain_key(self) -> None:
        raw = {"warn": {"notify": ["slack"]}}
        result = _parse_routing(raw)
        assert result["warn"].chain == []
        assert result["warn"].notify == ["slack"]

    def test_dict_missing_notify_key(self) -> None:
        raw = {"warn": {"chain": ["triage"]}}
        result = _parse_routing(raw)
        assert result["warn"].chain == ["triage"]
        assert result["warn"].notify == []

    def test_unexpected_type_becomes_none(self) -> None:
        raw = {"warn": 42}
        result = _parse_routing(raw)
        assert result["warn"] is None

    def test_all_none_values(self) -> None:
        raw = {"critical": None, "warn": None, "info": None}
        result = _parse_routing(raw)
        assert all(v is None for v in result.values())


class TestLoadConfigRouting:
    """Test that load_config parses routing into RouteConfig objects."""

    def _write_config(self, tmp_path: Path, yaml_text: str) -> None:
        (tmp_path / "mallcop.yaml").write_text(yaml_text)

    def test_old_format_yaml(self, tmp_path: Path) -> None:
        self._write_config(tmp_path, textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing:
              critical: triage
              warn: triage
              info: null
            budget: {}
        """))
        config = load_config(tmp_path)
        assert isinstance(config.routing["critical"], RouteConfig)
        assert config.routing["critical"].chain == ["triage"]
        assert config.routing["critical"].notify == []
        assert config.routing["info"] is None

    def test_new_format_yaml(self, tmp_path: Path) -> None:
        self._write_config(tmp_path, textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing:
              critical:
                chain: [triage, investigate]
                notify: [slack, email]
              warn:
                chain: [triage]
                notify: [slack]
              info: null
            budget: {}
        """))
        config = load_config(tmp_path)
        assert config.routing["critical"].chain == ["triage", "investigate"]
        assert config.routing["critical"].notify == ["slack", "email"]
        assert config.routing["warn"].chain == ["triage"]
        assert config.routing["warn"].notify == ["slack"]
        assert config.routing["info"] is None

    def test_mixed_format_yaml(self, tmp_path: Path) -> None:
        self._write_config(tmp_path, textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing:
              critical:
                chain: [triage, investigate]
                notify: [slack]
              warn: triage
            budget: {}
        """))
        config = load_config(tmp_path)
        assert config.routing["critical"].chain == ["triage", "investigate"]
        assert config.routing["warn"].chain == ["triage"]
        assert config.routing["warn"].notify == []
