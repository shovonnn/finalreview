from __future__ import annotations

import time
from abc import ABC, abstractmethod

from pydantic import ValidationError

from ..config import AppSettings
from ..exceptions import ProviderError
from ..models import CandidatePack, Finding, ProviderKind, RepositorySummary
from ..prompts import (
    build_judge_system_prompt,
    build_judge_user_prompt,
    build_review_system_prompt,
    build_review_user_prompt,
)
from ..utils import extract_json_payload


class BaseProvider(ABC):
    kind: ProviderKind

    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    @property
    def model_name(self) -> str | None:
        return self.settings.model

    @abstractmethod
    def validate_configuration(self) -> None:
        """Raise ProviderError when local provider configuration is unusable."""

    @abstractmethod
    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError

    def _complete(self, system_prompt: str, user_prompt: str) -> str:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return self._send_completion(system_prompt, user_prompt)
            except ProviderError as exc:
                last_error = exc
            except Exception as exc:  # pragma: no cover - defensive boundary
                last_error = exc
            if attempt < 2:
                time.sleep(min(2**attempt, 2))
        raise ProviderError(f"{self.kind.value} provider request failed.") from last_error

    def review_candidate(
        self, summary: RepositorySummary, candidate: CandidatePack
    ) -> list[Finding]:
        response = self._complete(
            build_review_system_prompt(),
            build_review_user_prompt(summary, candidate),
        )
        return self._parse_findings(response)

    def judge_findings(self, summary: RepositorySummary, findings: list[Finding]) -> list[Finding]:
        response = self._complete(
            build_judge_system_prompt(),
            build_judge_user_prompt(summary, findings),
        )
        return self._parse_findings(response)

    def _parse_findings(self, text: str) -> list[Finding]:
        try:
            payload = extract_json_payload(text)
            raw_findings = payload.get("findings", []) if isinstance(payload, dict) else payload
            findings = []
            for raw in raw_findings:
                finding = Finding.model_validate(raw)
                findings.append(
                    finding.model_copy(
                        update={
                            "provider": self.kind.value,
                            "model": self.model_name,
                            "source": f"{self.kind.value}-agent",
                        }
                    )
                )
            return findings
        except (ValueError, ValidationError) as exc:
            raise ProviderError(
                f"{self.kind.value} provider returned invalid JSON output."
            ) from exc


class NoOpProvider(BaseProvider):
    kind = ProviderKind.NONE

    def validate_configuration(self) -> None:
        return None

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        raise ProviderError("No-op provider does not support remote completions.")
