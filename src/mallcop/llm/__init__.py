"""LLM clients: Anthropic Messages API, AWS Bedrock, OpenAI-compatible, and Claude Code CLI."""

from __future__ import annotations

import logging
from typing import Any

from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall  # noqa: F401
from mallcop.config import DEFAULT_API_URL, DEFAULT_INFERENCE_URL, LLMConfig

from mallcop.llm.anthropic import AnthropicClient  # noqa: F401
from mallcop.llm.managed import ManagedClient  # noqa: F401
from mallcop.llm.bedrock import BedrockClient  # noqa: F401
from mallcop.llm.openai_compat import OpenAICompatClient  # noqa: F401
from mallcop.llm.bedrock_mantle import BedrockMantleClient  # noqa: F401
from mallcop.llm.claude_code import ClaudeCodeClient  # noqa: F401

__all__ = [
    "LLMAPIError",
    "LLMClient",
    "LLMResponse",
    "ToolCall",
    "AnthropicClient",
    "BedrockClient",
    "BedrockMantleClient",
    "ManagedClient",
    "OpenAICompatClient",
    "ClaudeCodeClient",
    "register_provider",
    "_PROVIDERS",
    "build_llm_client",
    "resolve_model_id",
]

_log = logging.getLogger(__name__)

_MODEL_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-6",
}


def resolve_model_id(alias: str, default: str | None = None) -> str:
    """Map a short model alias to a full Anthropic model ID."""
    if alias in _MODEL_ALIASES:
        return _MODEL_ALIASES[alias]
    return alias


# --- Provider registry ---

_PROVIDERS: dict[str, Any] = {}


def register_provider(name: str):
    """Decorator that registers a builder function in _PROVIDERS."""
    def decorator(fn):
        _PROVIDERS[name] = fn
        return fn
    return decorator


@register_provider("anthropic")
def _build_anthropic(llm_config: LLMConfig) -> LLMClient | None:
    if not llm_config.api_key:
        return None
    return AnthropicClient(
        api_key=llm_config.api_key,
        default_model=llm_config.default_model,
    )


@register_provider("managed")
def _build_managed(llm_config: LLMConfig) -> LLMClient | None:
    if not llm_config.api_key:
        _log.warning("Managed provider requires api_key (service_token)")
        return None
    endpoint = llm_config.endpoint or DEFAULT_API_URL
    return ManagedClient(
        endpoint=endpoint,
        service_token=llm_config.api_key,
        default_model=llm_config.default_model,
    )


@register_provider("bedrock")
def _build_bedrock(llm_config: LLMConfig) -> LLMClient | None:
    return BedrockClient(
        model=llm_config.default_model,
        region=llm_config.endpoint or "us-east-1",
        access_key=llm_config.api_key,
        secret_key=llm_config.secret_key,
    )


@register_provider("bedrock-mantle")
def _build_bedrock_mantle(llm_config: LLMConfig) -> LLMClient | None:
    return BedrockMantleClient(
        model=llm_config.default_model,
        region=llm_config.endpoint or "us-east-1",
        access_key=llm_config.api_key or "",
        secret_key=llm_config.secret_key or "",
    )


@register_provider("openai-compat")
def _build_openai_compat(llm_config: LLMConfig) -> LLMClient | None:
    if not llm_config.endpoint:
        return None
    return OpenAICompatClient(
        endpoint=llm_config.endpoint,
        api_key=llm_config.api_key,
        model=llm_config.default_model,
    )


def build_llm_client(
    llm_config: LLMConfig | None,
    backend: str = "anthropic",
    pro_config: Any | None = None,
) -> LLMClient | None:
    """Build an LLM client from config."""
    if backend == "claude-code":
        model = "sonnet"
        if llm_config and llm_config.default_model:
            model = llm_config.default_model
        return ClaudeCodeClient(model=model)

    if pro_config is not None:
        service_token = getattr(pro_config, "service_token", None)
        if service_token and (
            llm_config is None or llm_config.provider == "anthropic"
        ):
            inference_url = getattr(pro_config, "inference_url", None) or DEFAULT_INFERENCE_URL
            return ManagedClient(
                endpoint=inference_url,
                service_token=service_token,
            )

    if llm_config is None:
        return None

    builder = _PROVIDERS.get(llm_config.provider)
    if builder is not None:
        return builder(llm_config)

    _log.warning("Unsupported LLM provider: %s", llm_config.provider)
    return None
