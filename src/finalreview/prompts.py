from __future__ import annotations

import json

from .models import CandidatePack, Finding, RepositorySummary


def build_review_system_prompt() -> str:
    return (
        "You are a senior application security reviewer. "
        "Review the candidate context carefully, reason about exploitability, "
        "and return only a JSON object with a top-level 'findings' array. "
        "Include only credible vulnerabilities. Use severities critical/high/medium/low "
        "and confidences high/medium/low. Prefer no finding over speculation."
    )


def build_review_user_prompt(summary: RepositorySummary, candidate: CandidatePack) -> str:
    signal_payload = [signal.model_dump(mode="json") for signal in candidate.signals]
    return (
        "Repository summary:\n"
        f"{json.dumps(summary.model_dump(mode='json', exclude={'files'}), indent=2)}\n\n"
        "Candidate metadata:\n"
        f"{json.dumps(candidate.model_dump(mode='json', exclude={'context'}), indent=2)}\n\n"
        "Candidate context:\n"
        f"{candidate.context}\n\n"
        "Return JSON with this shape:\n"
        "{"
        '"findings": ['
        "{"
        '"title": str, '
        '"severity": "critical|high|medium|low", '
        '"confidence": "high|medium|low", '
        '"cwe": str|null, '
        '"summary": str, '
        '"reasoning": str, '
        '"remediation": str, '
        '"references": [{"path": str, "line_start": int|null, "line_end": int|null}], '
        '"evidence": [{"path": str, "excerpt": str, "line_start": int|null, "line_end": int|null}], '
        '"rule_id": str|null, '
        '"tags": [str]'
        "}"
        "]"
        "}\n\n"
        f"Deterministic signals for context:\n{json.dumps(signal_payload, indent=2)}"
    )


def build_judge_system_prompt() -> str:
    return (
        "You are the adjudication stage of a security review agent. "
        "Deduplicate overlapping findings, suppress weak false positives, "
        "and preserve only vulnerabilities that are supported by the evidence. "
        "Return only JSON with a top-level 'findings' array."
    )


def build_judge_user_prompt(summary: RepositorySummary, findings: list[Finding]) -> str:
    finding_payload = [finding.model_dump(mode="json") for finding in findings]
    return (
        "Repository summary:\n"
        f"{json.dumps(summary.model_dump(mode='json', exclude={'files'}), indent=2)}\n\n"
        "Candidate findings:\n"
        f"{json.dumps(finding_payload, indent=2)}\n\n"
        "Return the same JSON finding shape, preserving only credible vulnerabilities."
    )
