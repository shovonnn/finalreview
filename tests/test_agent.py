from __future__ import annotations

from finalreview.agent import run_agent_review
from finalreview.config import AppSettings
from finalreview.models import (
    CandidatePack,
    Confidence,
    ProviderKind,
    RepositorySummary,
    Severity,
    Signal,
    SourceFile,
)
from finalreview.providers.base import BaseProvider


class RetryingTestProvider(BaseProvider):
    kind = ProviderKind.OPENAI

    def __init__(self, settings: AppSettings) -> None:
        super().__init__(settings)
        self.calls = 0

    def validate_configuration(self) -> None:
        return None

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("temporary failure")
        return '{"findings": []}'


class JudgeProvider(BaseProvider):
    kind = ProviderKind.OPENAI

    def __init__(self, settings: AppSettings) -> None:
        super().__init__(settings)
        self.calls = 0

    def validate_configuration(self) -> None:
        return None

    def _send_completion(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            return """
            {
              "findings": [{
                "title": "Confirmed eval RCE",
                "severity": "high",
                "confidence": "high",
                "cwe": "CWE-95",
                "summary": "eval is reachable.",
                "reasoning": "The data flow is unsafe.",
                "remediation": "Remove eval.",
                "references": [{"path": "app.py", "line_start": 1, "line_end": 1}],
                "evidence": [],
                "rule_id": "agent-confirmed-eval",
                "tags": ["python"]
              }]
            }
            """
        return """
        {
          "findings": [{
            "title": "Confirmed eval RCE",
            "severity": "high",
            "confidence": "high",
            "cwe": "CWE-95",
            "summary": "eval is reachable.",
            "reasoning": "The data flow is unsafe.",
            "remediation": "Remove eval.",
            "references": [{"path": "app.py", "line_start": 1, "line_end": 1}],
            "evidence": [],
            "rule_id": "agent-confirmed-eval",
            "tags": ["python"]
          }]
        }
        """


def test_provider_retries_and_parses_json():
    provider = RetryingTestProvider(AppSettings(provider=ProviderKind.OPENAI, model="x"))
    summary = RepositorySummary(root=".", file_count=0, files=[])
    candidate = CandidatePack(
        id="candidate",
        path="app.py",
        language="python",
        rationale="test",
        priority=1,
        context="eval(user_input)",
        signals=[],
    )

    findings = provider.review_candidate(summary, candidate)

    assert findings == []
    assert provider.calls == 2


def test_agent_review_honors_budget_and_judges_findings(tmp_path):
    app_path = tmp_path / "app.py"
    app_path.write_text("eval(user_input)\n", encoding="utf-8")
    summary = RepositorySummary(
        root=tmp_path,
        file_count=1,
        files=[
            SourceFile(
                path=app_path,
                relative_path="app.py",
                language="python",
                surfaces=["http"],
                size=app_path.stat().st_size,
                line_count=1,
            )
        ],
    )
    signals = [
        Signal(
            rule_id="py-eval-exec",
            title="Dynamic code execution",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-95",
            summary="eval is used",
            reasoning="unsafe",
            remediation="remove eval",
            path="app.py",
            line_start=1,
            line_end=1,
            tags=["python"],
        )
    ]
    provider = JudgeProvider(AppSettings(provider=ProviderKind.OPENAI, model="x", max_llm_calls=2))

    candidates, findings = run_agent_review(summary, signals, [], provider.settings, provider)

    assert len(candidates) == 1
    assert len(findings) == 1
    assert findings[0].title == "Confirmed eval RCE"
    assert provider.calls == 2
