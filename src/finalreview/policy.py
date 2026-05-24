from __future__ import annotations

from .models import Confidence, Finding, Severity


def is_blocking(
    severity: Severity,
    confidence: Confidence,
    *,
    fail_on: Severity,
    min_confidence: Confidence,
) -> bool:
    if fail_on == Severity.NEVER:
        return False
    return severity.rank >= fail_on.rank and confidence.rank >= min_confidence.rank


def apply_policy(
    findings: list[Finding],
    *,
    fail_on: Severity,
    min_confidence: Confidence,
) -> list[Finding]:
    return [
        finding.model_copy(
            update={
                "blocking": is_blocking(
                    finding.severity,
                    finding.confidence,
                    fail_on=fail_on,
                    min_confidence=min_confidence,
                )
            }
        )
        for finding in findings
    ]
