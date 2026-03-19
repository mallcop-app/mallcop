"""Tests for config loading, secret resolution, and budget defaults."""

import os
import textwrap
from pathlib import Path

import pytest

from mallcop.config import load_config, MallcopConfig, ConfigError, RouteConfig
from mallcop.secrets import SecretProvider, EnvSecretProvider


# --- Sample config YAML ---

FULL_CONFIG_YAML = textwrap.dedent("""\
    secrets:
      backend: env

    connectors:
      azure:
        tenant_id: ${AZURE_TENANT_ID}
        client_id: ${AZURE_CLIENT_ID}
        client_secret: ${AZURE_CLIENT_SECRET}
      github:
        token: ${GITHUB_TOKEN}

    routing:
      info: null
      warn: triage
      critical: triage

    actor_chain:
      triage:
        routes_to: notify-teams
      notify-teams:
        routes_to: null

    budget:
      max_findings_for_actors: 25
      max_tokens_per_run: 50000
      max_tokens_per_finding: 5000
""")

MINIMAL_CONFIG_YAML = textwrap.dedent("""\
    secrets:
      backend: env

    connectors:
      github:
        token: ${GITHUB_TOKEN}

    routing:
      info: null
      warn: triage
      critical: triage

    actor_chain:
      triage:
        routes_to: null
""")

NO_BUDGET_YAML = textwrap.dedent("""\
    secrets:
      backend: env

    connectors:
      github:
        token: mytoken

    routing:
      info: null
      warn: triage
      critical: triage

    actor_chain:
      triage:
        routes_to: null
""")


class TestSecretProviderABC:
    def test_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            SecretProvider()  # type: ignore[abstract]

    def test_has_resolve_method(self) -> None:
        assert hasattr(SecretProvider, "resolve")


class TestEnvSecretProvider:
    def test_resolves_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_SECRET", "s3cret")
        provider = EnvSecretProvider()
        assert provider.resolve("MY_SECRET") == "s3cret"

    def test_missing_var_raises(self) -> None:
        provider = EnvSecretProvider()
        # Use a var name that definitely does not exist
        with pytest.raises(ConfigError, match="MY_NONEXISTENT_VAR_12345"):
            provider.resolve("MY_NONEXISTENT_VAR_12345")

    def test_empty_var_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMPTY_VAR", "")
        provider = EnvSecretProvider()
        assert provider.resolve("EMPTY_VAR") == ""

    def test_env_provider_zero_value_returns_zero_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvSecretProvider.resolve() with a var set to "0" returns "0", not None/falsy."""
        monkeypatch.setenv("MY_ZERO_VAR", "0")
        provider = EnvSecretProvider()
        result = provider.resolve("MY_ZERO_VAR")
        assert result == "0"

    def test_env_provider_false_string_returns_false_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EnvSecretProvider.resolve() with a var set to "false" returns "false", not None."""
        monkeypatch.setenv("MY_FALSE_VAR", "false")
        provider = EnvSecretProvider()
        result = provider.resolve("MY_FALSE_VAR")
        assert result == "false"

    def test_config_error_importable_from_secrets(self) -> None:
        """ConfigError is importable directly from mallcop.secrets."""
        from mallcop.secrets import ConfigError as SecretsConfigError
        from mallcop.config import ConfigError as ConfigConfigError
        # Both import paths refer to the same class
        assert SecretsConfigError is ConfigConfigError

    def test_secret_provider_abstract_cannot_instantiate(self) -> None:
        """SecretProvider cannot be directly instantiated (ABC enforcement)."""
        with pytest.raises(TypeError):
            SecretProvider()  # type: ignore[abstract]


class TestLoadConfig:
    def _write_config(self, tmp_path: Path, content: str) -> Path:
        config_file = tmp_path / "mallcop.yaml"
        config_file.write_text(content)
        return config_file

    def test_loads_full_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AZURE_TENANT_ID", "tenant-1")
        monkeypatch.setenv("AZURE_CLIENT_ID", "client-1")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-1")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc123")
        self._write_config(tmp_path, FULL_CONFIG_YAML)

        config = load_config(tmp_path)

        assert isinstance(config, MallcopConfig)

    def test_parses_connectors_with_resolved_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AZURE_TENANT_ID", "tenant-1")
        monkeypatch.setenv("AZURE_CLIENT_ID", "client-1")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-1")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc123")
        self._write_config(tmp_path, FULL_CONFIG_YAML)

        config = load_config(tmp_path)

        assert "azure" in config.connectors
        assert config.connectors["azure"]["tenant_id"] == "tenant-1"
        assert config.connectors["azure"]["client_id"] == "client-1"
        assert config.connectors["azure"]["client_secret"] == "secret-1"
        assert "github" in config.connectors
        assert config.connectors["github"]["token"] == "ghp_abc123"

    def test_parses_routing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AZURE_TENANT_ID", "t")
        monkeypatch.setenv("AZURE_CLIENT_ID", "c")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
        monkeypatch.setenv("GITHUB_TOKEN", "g")
        self._write_config(tmp_path, FULL_CONFIG_YAML)

        config = load_config(tmp_path)

        assert config.routing["info"] is None
        assert isinstance(config.routing["warn"], RouteConfig)
        assert config.routing["warn"].chain == ["triage"]
        assert config.routing["warn"].notify == []
        assert isinstance(config.routing["critical"], RouteConfig)
        assert config.routing["critical"].chain == ["triage"]

    def test_parses_actor_chain(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AZURE_TENANT_ID", "t")
        monkeypatch.setenv("AZURE_CLIENT_ID", "c")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
        monkeypatch.setenv("GITHUB_TOKEN", "g")
        self._write_config(tmp_path, FULL_CONFIG_YAML)

        config = load_config(tmp_path)

        assert config.actor_chain["triage"]["routes_to"] == "notify-teams"
        assert config.actor_chain["notify-teams"]["routes_to"] is None

    def test_parses_budget(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AZURE_TENANT_ID", "t")
        monkeypatch.setenv("AZURE_CLIENT_ID", "c")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
        monkeypatch.setenv("GITHUB_TOKEN", "g")
        self._write_config(tmp_path, FULL_CONFIG_YAML)

        config = load_config(tmp_path)

        assert config.budget.max_findings_for_actors == 25
        assert config.budget.max_donuts_per_run == 50000
        assert config.budget.max_donuts_per_finding == 5000

    def test_default_budget_when_not_specified(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "g")
        self._write_config(tmp_path, NO_BUDGET_YAML)

        config = load_config(tmp_path)

        # Defaults from design doc
        assert config.budget.max_findings_for_actors == 25
        assert config.budget.max_donuts_per_run == 50000
        assert config.budget.max_donuts_per_finding == 5000

    def test_missing_secret_raises_clear_error(self, tmp_path: Path) -> None:
        self._write_config(tmp_path, MINIMAL_CONFIG_YAML)
        # GITHUB_TOKEN not set in environment

        with pytest.raises(ConfigError, match="GITHUB_TOKEN"):
            load_config(tmp_path)

    def test_missing_config_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="mallcop.yaml"):
            load_config(tmp_path)

    def test_secrets_backend_stored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "g")
        self._write_config(tmp_path, NO_BUDGET_YAML)

        config = load_config(tmp_path)

        assert config.secrets_backend == "env"

    def test_literal_values_not_resolved(self, tmp_path: Path) -> None:
        """Values without ${} should pass through as-is."""
        self._write_config(tmp_path, NO_BUDGET_YAML)

        config = load_config(tmp_path)

        # "mytoken" is literal, not a ${VAR} reference
        assert config.connectors["github"]["token"] == "mytoken"

    def test_partial_budget_uses_defaults_for_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors:
              github:
                token: literal

            routing:
              info: null
              warn: triage
              critical: triage

            actor_chain:
              triage:
                routes_to: null

            budget:
              max_findings_for_actors: 10
        """)
        self._write_config(tmp_path, yaml_content)

        config = load_config(tmp_path)

        assert config.budget.max_findings_for_actors == 10
        assert config.budget.max_donuts_per_run == 50000
        assert config.budget.max_donuts_per_finding == 5000

    def test_nested_secret_references_in_connectors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ensure ${VAR} works in all connector config values."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors:
              custom:
                api_key: ${CUSTOM_KEY}
                endpoint: https://example.com

            routing:
              info: null
              warn: triage
              critical: triage

            actor_chain:
              triage:
                routes_to: null
        """)
        monkeypatch.setenv("CUSTOM_KEY", "mykey123")
        self._write_config(tmp_path, yaml_content)

        config = load_config(tmp_path)

        assert config.connectors["custom"]["api_key"] == "mykey123"
        assert config.connectors["custom"]["endpoint"] == "https://example.com"

    def test_budget_old_token_field_names_backward_compat(
        self, tmp_path: Path
    ) -> None:
        """Old max_tokens_per_run / max_tokens_per_finding YAML keys map to donuts fields."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors:
              github:
                token: literal

            routing: {}
            actor_chain: {}

            budget:
              max_findings_for_actors: 20
              max_tokens_per_run: 30000
              max_tokens_per_finding: 3000
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        # Old YAML field names are mapped to new donut fields
        assert config.budget.max_findings_for_actors == 20
        assert config.budget.max_donuts_per_run == 30000
        assert config.budget.max_donuts_per_finding == 3000

    def test_budget_new_donut_field_names(
        self, tmp_path: Path
    ) -> None:
        """New max_donuts_per_run / max_donuts_per_finding YAML keys are parsed correctly."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors:
              github:
                token: literal

            routing: {}
            actor_chain: {}

            budget:
              max_findings_for_actors: 15
              max_donuts_per_run: 25000
              max_donuts_per_finding: 2500
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.budget.max_findings_for_actors == 15
        assert config.budget.max_donuts_per_run == 25000
        assert config.budget.max_donuts_per_finding == 2500


# --- Baseline config ---


class TestBaselineConfig:
    def _write_config(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "mallcop.yaml").write_text(content)

    def test_baseline_default_when_section_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When baseline section is absent, defaults to 30 days."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.baseline.window_days == 30

    def test_baseline_custom_window_days(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """baseline.window_days reads from config."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            baseline:
              window_days: 60
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.baseline.window_days == 60

    def test_baseline_window_days_default_in_section(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty baseline section uses default window_days."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            baseline: {}
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.baseline.window_days == 30


# --- Pro config URL resolution ---


class TestProConfigUrlResolution:
    def _write_config(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "mallcop.yaml").write_text(content)

    def test_pro_account_url_resolved_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """account_url with ${VAR} reference resolves through SecretProvider."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            pro:
              account_id: acct_123
              service_token: tok_abc
              account_url: ${MALLCOP_ACCOUNT_URL}
        """)
        monkeypatch.setenv("MALLCOP_ACCOUNT_URL", "https://custom.api.example.com")
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.account_url == "https://custom.api.example.com"

    def test_pro_inference_url_resolved_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """inference_url with ${VAR} reference resolves through SecretProvider."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            pro:
              account_id: acct_123
              service_token: tok_abc
              inference_url: ${MALLCOP_INFERENCE_URL}
        """)
        monkeypatch.setenv("MALLCOP_INFERENCE_URL", "https://inference.example.com")
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.inference_url == "https://inference.example.com"

    def test_pro_urls_literal_values_pass_through(self, tmp_path: Path) -> None:
        """Literal URL values (no ${}) pass through unchanged."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            pro:
              account_id: acct_123
              service_token: tok_abc
              account_url: https://literal.example.com
              inference_url: https://inference.literal.com
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.account_url == "https://literal.example.com"
        assert config.pro.inference_url == "https://inference.literal.com"

    def test_pro_account_url_default_when_not_specified(self, tmp_path: Path) -> None:
        """account_url defaults to https://api.mallcop.app when omitted."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            pro:
              account_id: acct_123
              service_token: tok_abc
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.account_url == "https://api.mallcop.app"


# ─── 5.6: _parse_routing and _parse_llm edge cases ────────────────────────────


class TestParseRoutingEdgeCases:
    """mallcop-ak1n.5.6: _parse_routing edge cases."""

    def test_parse_routing_integer_value_treated_as_none(self) -> None:
        """Unexpected integer value for a severity should yield None (fallthrough)."""
        from mallcop.config import _parse_routing

        result = _parse_routing({"warn": 42})
        assert result["warn"] is None

    def test_parse_routing_list_value_treated_as_none(self) -> None:
        """Unexpected list value for a severity should yield None (fallthrough)."""
        from mallcop.config import _parse_routing

        result = _parse_routing({"warn": ["triage", "notify"]})
        assert result["warn"] is None

    def test_parse_routing_new_dict_format_chain_and_notify(self) -> None:
        """New dict format {chain: [...], notify: [...]} is parsed into RouteConfig."""
        from mallcop.config import _parse_routing, RouteConfig

        raw = {"warn": {"chain": ["triage"], "notify": ["slack-channel"]}}
        result = _parse_routing(raw)
        assert isinstance(result["warn"], RouteConfig)
        assert result["warn"].chain == ["triage"]
        assert result["warn"].notify == ["slack-channel"]

    def test_parse_routing_dict_format_defaults_missing_keys(self) -> None:
        """Dict format with only 'chain' (no 'notify') defaults notify to []."""
        from mallcop.config import _parse_routing, RouteConfig

        raw = {"critical": {"chain": ["escalate"]}}
        result = _parse_routing(raw)
        assert isinstance(result["critical"], RouteConfig)
        assert result["critical"].chain == ["escalate"]
        assert result["critical"].notify == []

    def test_parse_routing_null_value_stays_none(self) -> None:
        """Explicit None in YAML (info: null) should produce None in routing."""
        from mallcop.config import _parse_routing

        result = _parse_routing({"info": None})
        assert result["info"] is None

    def test_parse_routing_empty_dict_returns_empty(self) -> None:
        """Empty routing dict returns empty result."""
        from mallcop.config import _parse_routing

        assert _parse_routing({}) == {}

    def test_parse_routing_none_returns_empty(self) -> None:
        """None input returns empty dict."""
        from mallcop.config import _parse_routing

        assert _parse_routing(None) == {}


class TestParseLLMEdgeCases:
    """mallcop-ak1n.5.6: _parse_llm edge cases."""

    def _env_provider(self) -> "EnvSecretProvider":
        return EnvSecretProvider()

    def test_parse_llm_bedrock_no_api_key_returns_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """For bedrock provider, api_key is optional — config is returned even with empty key."""
        from mallcop.config import _parse_llm, LLMConfig

        provider = EnvSecretProvider()
        raw = {"provider": "bedrock", "endpoint": "us-east-1"}
        result = _parse_llm(raw, provider)
        assert result is not None
        assert result.provider == "bedrock"
        assert result.api_key == ""

    def test_parse_llm_anthropic_missing_api_key_returns_none(self) -> None:
        """For anthropic provider, missing api_key returns None."""
        from mallcop.config import _parse_llm

        provider = EnvSecretProvider()
        raw = {"provider": "anthropic"}
        result = _parse_llm(raw, provider)
        assert result is None

    def test_parse_llm_none_section_returns_none(self) -> None:
        """None input returns None."""
        from mallcop.config import _parse_llm

        result = _parse_llm(None, EnvSecretProvider())
        assert result is None

    def test_parse_llm_openai_compat_with_endpoint(self) -> None:
        """openai-compat provider with endpoint and no api_key is allowed."""
        from mallcop.config import _parse_llm

        provider = EnvSecretProvider()
        raw = {
            "provider": "openai-compat",
            "endpoint": "https://my-llm.internal",
            "default_model": "llama-3",
        }
        result = _parse_llm(raw, provider)
        assert result is not None
        assert result.provider == "openai-compat"
        assert result.endpoint == "https://my-llm.internal"


class TestLoadConfigEdgeCases:
    """mallcop-ak1n.5.6: load_config edge cases."""

    def _write_config(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "mallcop.yaml").write_text(content)

    def test_unknown_backend_raises_config_error(self, tmp_path: Path) -> None:
        """Unknown secrets backend raises ConfigError with informative message."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: vault

            connectors: {}
            routing: {}
            actor_chain: {}
        """)
        self._write_config(tmp_path, yaml_content)
        with pytest.raises(ConfigError, match="vault"):
            load_config(tmp_path)

    def test_squelch_null_defaults_to_five(self, tmp_path: Path) -> None:
        """squelch: null in YAML produces config.squelch == 5."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}
            squelch: null
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert config.squelch == 5

    def test_actor_non_dict_value_silently_skipped(self, tmp_path: Path) -> None:
        """Non-dict actor config is silently skipped (no crash, no entry in actors dict)."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            actors:
              triage: "not_a_dict"
              valid_actor:
                model: haiku
        """)
        self._write_config(tmp_path, yaml_content)
        config = load_config(tmp_path)
        assert "triage" not in config.actors
        assert "valid_actor" in config.actors

    def test_pro_inference_url_env_missing_falls_back_to_empty(
        self, tmp_path: Path
    ) -> None:
        """When inference_url references a missing env var, it falls back to empty string."""
        yaml_content = textwrap.dedent("""\
            secrets:
              backend: env

            connectors: {}
            routing: {}
            actor_chain: {}

            pro:
              account_id: acct_123
              service_token: tok_abc
              inference_url: ${NONEXISTENT_INFERENCE_URL_XYZ}
        """)
        self._write_config(tmp_path, yaml_content)
        # Should NOT raise — graceful fallback
        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.inference_url == ""


# ---------------------------------------------------------------------------
# Squelch range validation (bead 2.30)
# ---------------------------------------------------------------------------


class TestSquelchRangeValidation:
    """squelch must be validated as 0-10 and raise ConfigError for out-of-range values."""

    def _write_config(self, tmp_path: Path, squelch_value: str | int | None) -> Path:
        yaml_content = f"""\
secrets:
  backend: env
connectors: {{}}
routing: {{}}
actor_chain: {{}}
squelch: {squelch_value}
"""
        cfg = tmp_path / "mallcop.yaml"
        cfg.write_text(yaml_content)
        return tmp_path

    def test_squelch_zero_is_valid(self, tmp_path: Path) -> None:
        path = self._write_config(tmp_path, 0)
        config = load_config(path)
        assert config.squelch == 0

    def test_squelch_ten_is_valid(self, tmp_path: Path) -> None:
        path = self._write_config(tmp_path, 10)
        config = load_config(path)
        assert config.squelch == 10

    def test_squelch_five_is_valid(self, tmp_path: Path) -> None:
        path = self._write_config(tmp_path, 5)
        config = load_config(path)
        assert config.squelch == 5

    def test_squelch_eleven_raises_config_error(self, tmp_path: Path) -> None:
        """squelch: 11 is out of range and must raise ConfigError."""
        path = self._write_config(tmp_path, 11)
        with pytest.raises(ConfigError, match="squelch"):
            load_config(path)

    def test_squelch_negative_raises_config_error(self, tmp_path: Path) -> None:
        """squelch: -1 is out of range and must raise ConfigError."""
        path = self._write_config(tmp_path, -1)
        with pytest.raises(ConfigError, match="squelch"):
            load_config(path)

    def test_squelch_hundred_raises_config_error(self, tmp_path: Path) -> None:
        """squelch: 100 would make threshold=10.0, squelching everything. Must raise."""
        path = self._write_config(tmp_path, 100)
        with pytest.raises(ConfigError, match="squelch"):
            load_config(path)
