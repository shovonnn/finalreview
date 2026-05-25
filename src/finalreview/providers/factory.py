from __future__ import annotations

from typing import TypedDict

from ..models import ProviderKind
from .anthropic import AnthropicProvider
from .base import BaseProvider, NoOpProvider
from .google import GoogleProvider
from .openai import AzureOpenAIProvider, OpenAICompatibleProvider, OpenAIProvider


class ProviderMetadata(TypedDict):
    class_: type[BaseProvider]
    extra: str | None
    api_key_env: str | None
    notes: str


PROVIDER_CATALOG: dict[ProviderKind, ProviderMetadata] = {
    ProviderKind.NONE: {
        "class_": NoOpProvider,
        "extra": None,
        "api_key_env": None,
        "notes": "Deterministic-only mode with no remote LLM calls.",
    },
    ProviderKind.OPENAI: {
        "class_": OpenAIProvider,
        "extra": "openai",
        "api_key_env": "OPENAI_API_KEY",
        "notes": "Native OpenAI adapter using the OpenAI Python SDK.",
    },
    ProviderKind.ANTHROPIC: {
        "class_": AnthropicProvider,
        "extra": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
        "notes": "Native Anthropic adapter using the Anthropic Python SDK.",
    },
    ProviderKind.GOOGLE: {
        "class_": GoogleProvider,
        "extra": "google",
        "api_key_env": "GOOGLE_API_KEY",
        "notes": "Native Google adapter using the Google GenAI SDK.",
    },
    ProviderKind.AZURE_OPENAI: {
        "class_": AzureOpenAIProvider,
        "extra": "openai",
        "api_key_env": "AZURE_OPENAI_API_KEY",
        "notes": "Azure OpenAI adapter using the OpenAI Python SDK.",
    },
    ProviderKind.OPENAI_COMPATIBLE: {
        "class_": OpenAICompatibleProvider,
        "extra": "openai",
        "api_key_env": "OPENAI_API_KEY",
        "notes": "Generic OpenAI-compatible adapter for self-hosted and gateway endpoints.",
    },
}


def create_provider(settings) -> BaseProvider:  # type: ignore[no-untyped-def]
    provider_class = PROVIDER_CATALOG[settings.provider]["class_"]
    provider = provider_class(settings)
    provider.validate_configuration()
    return provider
