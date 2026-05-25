from __future__ import annotations

from ..config import read_api_key
from ..exceptions import ProviderError
from ..models import ProviderKind
from .base import BaseProvider


class AnthropicProvider(BaseProvider):
    kind = ProviderKind.ANTHROPIC

    def validate_configuration(self) -> None:
        try:
            import anthropic  # noqa: F401
        except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
            raise ProviderError(
                "Anthropic provider dependencies are missing. Install finalreview[anthropic]."
            ) from exc
        if not self.settings.model:
            raise ProviderError("A model must be provided for the selected provider.")
        if not read_api_key(self.settings.provider, self.settings.api_key_env):
            raise ProviderError("Missing API key for the selected provider.")

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        try:
            import anthropic
        except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderError(
                "Anthropic provider dependencies are missing. Install finalreview[anthropic]."
            ) from exc

        model = self.settings.model
        if not model:
            raise ProviderError("A model must be provided for the selected provider.")
        api_key = read_api_key(self.settings.provider, self.settings.api_key_env)
        if not api_key:
            raise ProviderError("Missing API key for the selected provider.")

        client = anthropic.Anthropic(api_key=api_key, timeout=self.settings.timeout_seconds)
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            temperature=0,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        chunks = [
            text
            for block in response.content
            if getattr(block, "type", "") == "text"
            for text in [getattr(block, "text", None)]
            if text
        ]
        if not chunks:
            raise ProviderError("Provider returned an empty response.")
        return "".join(chunks)
