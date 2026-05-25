from __future__ import annotations

from ..config import read_api_key
from ..exceptions import ProviderError
from ..models import ProviderKind
from .base import BaseProvider


class GoogleProvider(BaseProvider):
    kind = ProviderKind.GOOGLE

    def validate_configuration(self) -> None:
        try:
            from google import genai  # noqa: F401
        except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
            raise ProviderError(
                "Google provider dependencies are missing. Install finalreview[google]."
            ) from exc
        if not self.settings.model:
            raise ProviderError("A model must be provided for the selected provider.")
        if not read_api_key(self.settings.provider, self.settings.api_key_env):
            raise ProviderError("Missing API key for the selected provider.")

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        try:
            from google import genai
        except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderError(
                "Google provider dependencies are missing. Install finalreview[google]."
            ) from exc

        model = self.settings.model
        if not model:
            raise ProviderError("A model must be provided for the selected provider.")
        api_key = read_api_key(self.settings.provider, self.settings.api_key_env)
        if not api_key:
            raise ProviderError("Missing API key for the selected provider.")

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model,
            contents=f"{system_prompt}\n\n{user_prompt}",
            config={"temperature": 0},
        )
        text = getattr(response, "text", None)
        if not text:
            raise ProviderError("Provider returned an empty response.")
        return str(text)
