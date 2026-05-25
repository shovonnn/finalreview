from __future__ import annotations

from collections import deque

from ..models import ProviderKind
from .base import BaseProvider


class MockProvider(BaseProvider):
    """Test-only provider that consumes queued JSON strings."""

    kind = ProviderKind.OPENAI_COMPATIBLE

    def __init__(self, settings, responses: list[str]) -> None:  # type: ignore[no-untyped-def]
        super().__init__(settings)
        self.responses = deque(responses)

    def validate_configuration(self) -> None:
        return None

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        if not self.responses:
            return '{"findings": []}'
        return self.responses.popleft()
