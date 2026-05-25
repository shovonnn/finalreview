from __future__ import annotations

from ..config import read_api_key
from ..exceptions import ProviderError
from ..models import ProviderKind
from .base import BaseProvider


class OpenAIBaseProvider(BaseProvider):
    def validate_configuration(self) -> None:
        if not self.settings.model:
            raise ProviderError("A model must be provided for the selected provider.")
        self._build_openai_client()

    def _build_openai_client(self) -> object:
        try:
            from openai import AzureOpenAI, OpenAI
        except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderError(
                "OpenAI provider dependencies are missing. Install finalreview[openai]."
            ) from exc

        api_key = read_api_key(self.settings.provider, self.settings.api_key_env)
        if not api_key:
            raise ProviderError("Missing API key for the selected provider.")

        if self.settings.provider == ProviderKind.AZURE_OPENAI:
            if not self.settings.base_url:
                raise ProviderError("Azure OpenAI requires --base-url set to the Azure endpoint.")
            return AzureOpenAI(
                api_key=api_key,
                azure_endpoint=self.settings.base_url,
                api_version="2024-10-21",
                timeout=self.settings.timeout_seconds,
            )
        return OpenAI(
            api_key=api_key,
            base_url=self.settings.base_url,
            timeout=self.settings.timeout_seconds,
        )

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        model = self.settings.model
        if not model:
            raise ProviderError("A model must be provided for the selected provider.")
        client = self._build_openai_client()
        response = client.chat.completions.create(  # type: ignore[attr-defined]
            model=model,
            temperature=0,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.choices[0].message.content
        if not content:
            raise ProviderError("Provider returned an empty response.")
        return str(content)


class OpenAIProvider(OpenAIBaseProvider):
    kind = ProviderKind.OPENAI


class AzureOpenAIProvider(OpenAIBaseProvider):
    kind = ProviderKind.AZURE_OPENAI


class OpenAICompatibleProvider(OpenAIBaseProvider):
    kind = ProviderKind.OPENAI_COMPATIBLE
