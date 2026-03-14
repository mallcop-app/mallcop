"""Config loading: mallcop.yaml parsing and secret resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mallcop.secrets import ConfigError, SecretProvider, EnvSecretProvider

__all__ = ["load_config", "MallcopConfig", "BudgetConfig", "BaselineConfig", "LLMConfig", "RouteConfig", "ProConfig", "ConfigError", "_parse_routing"]

# Re-export ConfigError so tests can import from mallcop.config
ConfigError = ConfigError

# Default baseline window (days)
_DEFAULT_BASELINE_WINDOW_DAYS = 30

# Default budget values from design doc
_DEFAULT_MAX_FINDINGS_FOR_ACTORS = 25
_DEFAULT_MAX_TOKENS_PER_RUN = 50000
_DEFAULT_MAX_TOKENS_PER_FINDING = 5000

# Pattern for ${VAR_NAME} references
_SECRET_REF_PATTERN = re.compile(r"^\$\{([^}]+)\}$")


@dataclass
class LLMConfig:
    provider: str = "anthropic"
    api_key: str = ""
    default_model: str = "claude-haiku-4-5-20251001"
    endpoint: str = ""  # Custom endpoint URL for openai-compat; region for bedrock
    secret_key: str = ""  # AWS secret access key for bedrock provider


@dataclass
class BaselineConfig:
    window_days: int = _DEFAULT_BASELINE_WINDOW_DAYS


@dataclass
class BudgetConfig:
    max_findings_for_actors: int = _DEFAULT_MAX_FINDINGS_FOR_ACTORS
    max_tokens_per_run: int = _DEFAULT_MAX_TOKENS_PER_RUN
    max_tokens_per_finding: int = _DEFAULT_MAX_TOKENS_PER_FINDING


@dataclass
class RouteConfig:
    """Routing config for a single severity level."""
    chain: list[str]      # sequential investigation actors
    notify: list[str]     # parallel notification channels


def _parse_routing(raw: dict[str, Any] | None) -> dict[str, RouteConfig | None]:
    """Parse routing config, handling both old and new formats.

    Old format (string): ``severity: actor_name``
    New format (dict): ``severity: {chain: [...], notify: [...]}``
    """
    if raw is None:
        return {}
    result: dict[str, RouteConfig | None] = {}
    for severity, value in raw.items():
        if value is None:
            result[severity] = None
        elif isinstance(value, str):
            # Old format: severity -> actor name
            result[severity] = RouteConfig(chain=[value], notify=[])
        elif isinstance(value, dict):
            # New format
            result[severity] = RouteConfig(
                chain=value.get("chain", []),
                notify=value.get("notify", []),
            )
        else:
            result[severity] = None
    return result


@dataclass
class ProConfig:
    account_id: str = ""
    service_token: str = ""
    account_url: str = "https://api.mallcop.dev"
    inference_url: str = ""


@dataclass
class MallcopConfig:
    secrets_backend: str
    connectors: dict[str, dict[str, Any]]
    routing: dict[str, RouteConfig | None]
    actor_chain: dict[str, dict[str, Any]]
    budget: BudgetConfig
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    llm: LLMConfig | None = None
    actors: dict[str, dict[str, Any]] = field(default_factory=dict)
    pro: ProConfig | None = None
    squelch: int = 5  # 0-10: confidence gate; squelch/10 = threshold; 0=off, 10=max


def _resolve_value(value: Any, provider: SecretProvider) -> Any:
    """Resolve a single value. If it's a ${VAR} reference, resolve it."""
    if not isinstance(value, str):
        return value
    match = _SECRET_REF_PATTERN.match(value)
    if match:
        return provider.resolve(match.group(1))
    return value


def _resolve_connector_config(
    config: dict[str, Any], provider: SecretProvider
) -> dict[str, Any]:
    """Resolve all ${VAR} references in a connector's config dict."""
    resolved: dict[str, Any] = {}
    for key, value in config.items():
        resolved[key] = _resolve_value(value, provider)
    return resolved


def _get_secret_provider(backend: str) -> SecretProvider:
    """Return the appropriate SecretProvider for the given backend name."""
    if backend == "env":
        return EnvSecretProvider()
    raise ConfigError(f"Unknown secrets backend: '{backend}'. Supported: env")


def _parse_budget(raw: dict[str, Any] | None) -> BudgetConfig:
    """Parse budget section, using defaults for missing values."""
    if raw is None:
        return BudgetConfig()
    return BudgetConfig(
        max_findings_for_actors=raw.get(
            "max_findings_for_actors", _DEFAULT_MAX_FINDINGS_FOR_ACTORS
        ),
        max_tokens_per_run=raw.get(
            "max_tokens_per_run", _DEFAULT_MAX_TOKENS_PER_RUN
        ),
        max_tokens_per_finding=raw.get(
            "max_tokens_per_finding", _DEFAULT_MAX_TOKENS_PER_FINDING
        ),
    )


def _parse_baseline(raw: dict[str, Any] | None) -> BaselineConfig:
    """Parse baseline section, using defaults for missing values."""
    if raw is None:
        return BaselineConfig()
    return BaselineConfig(
        window_days=raw.get("window_days", _DEFAULT_BASELINE_WINDOW_DAYS),
    )


def _parse_llm(raw: dict[str, Any] | None, provider: SecretProvider) -> LLMConfig | None:
    """Parse llm section. Returns None if section missing.

    For anthropic provider, returns None if api_key is missing/unresolvable.
    For bedrock and openai-compat, api_key may be optional.
    """
    if raw is None:
        return None
    llm_provider = raw.get("provider", "anthropic")

    # Resolve api_key (may be a ${VAR} reference)
    api_key_raw = raw.get("api_key", "")
    try:
        api_key = _resolve_value(api_key_raw, provider) if api_key_raw else ""
    except ConfigError:
        api_key = ""

    # Resolve secret_key for bedrock
    secret_key_raw = raw.get("secret_key", "")
    try:
        secret_key = _resolve_value(secret_key_raw, provider) if secret_key_raw else ""
    except ConfigError:
        secret_key = ""

    # Resolve endpoint
    endpoint_raw = raw.get("endpoint", "")
    try:
        endpoint = _resolve_value(endpoint_raw, provider) if endpoint_raw else ""
    except ConfigError:
        endpoint = ""

    # For anthropic provider, api_key is required
    if llm_provider == "anthropic" and not api_key:
        return None

    return LLMConfig(
        provider=llm_provider,
        api_key=api_key,
        default_model=raw.get("default_model", "claude-haiku-4-5-20251001"),
        endpoint=endpoint,
        secret_key=secret_key,
    )


def _parse_pro(raw: dict[str, Any] | None, provider: SecretProvider) -> ProConfig | None:
    """Parse pro section. Returns None if section missing."""
    if not raw or not isinstance(raw, dict):
        return None
    service_token_raw = raw.get("service_token", "")
    try:
        service_token = _resolve_value(service_token_raw, provider) if service_token_raw else ""
    except ConfigError:
        service_token = ""
    # Resolve URL fields through SecretProvider (may reference env vars)
    account_url_raw = raw.get("account_url", "https://api.mallcop.dev")
    try:
        account_url = _resolve_value(account_url_raw, provider) if account_url_raw else "https://api.mallcop.dev"
    except ConfigError:
        account_url = account_url_raw  # Fall back to literal if env var missing

    inference_url_raw = raw.get("inference_url", "")
    try:
        inference_url = _resolve_value(inference_url_raw, provider) if inference_url_raw else ""
    except ConfigError:
        inference_url = ""

    return ProConfig(
        account_id=raw.get("account_id", ""),
        service_token=service_token,
        account_url=account_url,
        inference_url=inference_url,
    )


def load_config(config_dir: Path) -> MallcopConfig:
    """Load and parse mallcop.yaml from the given directory.

    Resolves all ${VAR} secret references through the configured backend.
    Raises ConfigError for missing files, missing secrets, or invalid config.
    """
    config_path = config_dir / "mallcop.yaml"
    if not config_path.exists():
        raise ConfigError(
            f"mallcop.yaml not found in {config_dir}. "
            f"Run 'mallcop init' to create one."
        )

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError("mallcop.yaml is empty or invalid.")

    # Secrets backend
    secrets_section = raw.get("secrets", {})
    backend = secrets_section.get("backend", "env")
    provider = _get_secret_provider(backend)

    # Connectors — resolve secret references
    raw_connectors = raw.get("connectors", {})
    connectors: dict[str, dict[str, Any]] = {}
    for name, connector_config in raw_connectors.items():
        connectors[name] = _resolve_connector_config(connector_config, provider)

    # Routing
    routing = _parse_routing(raw.get("routing", {}))

    # Actor chain
    actor_chain = raw.get("actor_chain", {})

    # Budget
    budget = _parse_budget(raw.get("budget"))

    # Baseline
    baseline_config = _parse_baseline(raw.get("baseline"))

    # LLM — graceful: if api_key can't be resolved, llm is None
    llm_config = _parse_llm(raw.get("llm"), provider)

    actors_config: dict[str, dict[str, Any]] = {}
    for actor_name, actor_cfg in raw.get("actors", {}).items():
        if isinstance(actor_cfg, dict):
            actors_config[actor_name] = {
                k: _resolve_value(v, provider) for k, v in actor_cfg.items()
            }

    # Pro config
    pro_config = _parse_pro(raw.get("pro"), provider)

    # Squelch: 0-10 integer gate, default 5
    squelch_raw = raw.get("squelch", 5)
    squelch = int(squelch_raw) if squelch_raw is not None else 5

    return MallcopConfig(
        secrets_backend=backend,
        connectors=connectors,
        routing=routing,
        actor_chain=actor_chain,
        budget=budget,
        baseline=baseline_config,
        llm=llm_config,
        actors=actors_config,
        pro=pro_config,
        squelch=squelch,
    )
