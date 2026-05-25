from __future__ import annotations

from collections import defaultdict

from .config import AppSettings
from .models import (
    CandidatePack,
    Confidence,
    FileReference,
    Finding,
    RepositorySummary,
    Severity,
    Signal,
)
from .providers.base import BaseProvider
from .utils import excerpt_lines, normalize_slug, read_text, truncate_middle


def _signal_to_finding(signal: Signal) -> Finding:
    return Finding(
        title=signal.title,
        severity=signal.severity,
        confidence=signal.confidence,
        cwe=signal.cwe,
        summary=signal.summary,
        reasoning=signal.reasoning,
        remediation=signal.remediation,
        references=[
            FileReference(
                path=signal.path,
                line_start=signal.line_start,
                line_end=signal.line_end,
            )
        ],
        evidence=[],
        tags=signal.tags,
        rule_id=signal.rule_id,
        source=signal.source,
    )


def select_candidates(
    summary: RepositorySummary,
    signals: list[Signal],
    settings: AppSettings,
) -> list[CandidatePack]:
    by_path: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        by_path[signal.path].append(signal)

    candidates: list[CandidatePack] = []
    for source_file in summary.files:
        file_signals = sorted(by_path.get(source_file.relative_path, []), key=lambda item: -item.priority)
        if not file_signals and not source_file.surfaces:
            continue

        base_priority = sum(signal.priority for signal in file_signals[:5])
        if not file_signals:
            base_priority = 5 + len(source_file.surfaces)

        text = read_text(source_file.path)
        if settings.whole_file_upload and len(text.encode("utf-8")) <= settings.max_candidate_bytes:
            context = text
        else:
            snippets = [
                excerpt_lines(text, signal.line_start, signal.line_end)
                for signal in file_signals[:3]
            ]
            context = "\n\n".join(snippets) if snippets else truncate_middle(text, settings.max_candidate_bytes)

        rationale = (
            f"surfaces={','.join(source_file.surfaces) or 'none'}; "
            f"signals={len(file_signals)}; language={source_file.language}"
        )
        candidates.append(
            CandidatePack(
                id=normalize_slug(source_file.relative_path),
                path=source_file.relative_path,
                language=source_file.language,
                surfaces=source_file.surfaces,
                rationale=rationale,
                priority=base_priority,
                context=context,
                signals=file_signals[:5],
            )
        )
    candidates.sort(key=lambda item: (-item.priority, item.path))
    return candidates[: settings.max_llm_calls]


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        existing = deduped.get(finding.fingerprint or "")
        if existing is None:
            deduped[finding.fingerprint or finding.id or finding.title] = finding
            continue
        if (finding.severity.rank, finding.confidence.rank) > (
            existing.severity.rank,
            existing.confidence.rank,
        ):
            deduped[finding.fingerprint or finding.id or finding.title] = finding
    return sorted(
        deduped.values(),
        key=lambda item: (-item.severity.rank, -item.confidence.rank, item.title, item.id or ""),
    )


def run_agent_review(
    summary: RepositorySummary,
    signals: list[Signal],
    external_findings: list[Finding],
    settings: AppSettings,
    provider: BaseProvider | None,
) -> tuple[list[CandidatePack], list[Finding]]:
    baseline_findings = [_signal_to_finding(signal) for signal in signals] + external_findings
    if provider is None or settings.max_llm_calls <= 0:
        return [], _dedupe_findings(baseline_findings)

    candidates = select_candidates(summary, signals, settings)
    reviewed_findings: list[Finding] = []
    review_budget = max(settings.max_llm_calls - 1, 0)
    for candidate in candidates[:review_budget]:
        reviewed_findings.extend(provider.review_candidate(summary, candidate))

    combined = _dedupe_findings(baseline_findings + reviewed_findings)
    if not combined:
        return candidates, []

    adjudicated = provider.judge_findings(summary, combined)
    preserved_baseline = [
        finding
        for finding in baseline_findings
        if finding.severity.rank >= Severity.HIGH.rank
        and finding.confidence.rank >= Confidence.HIGH.rank
    ]
    final_findings = _dedupe_findings(adjudicated + preserved_baseline)
    return candidates, final_findings
