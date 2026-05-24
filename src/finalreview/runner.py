from __future__ import annotations

import subprocess
from pathlib import Path

from .config import AppSettings
from .enrichers import collect_external_findings
from .exceptions import ConfigurationError, ScanRuntimeError
from .inventory import build_repository_summary
from .models import ScanResult, ScanScope
from .reporting import write_json_report, write_markdown_report, write_sarif_report
from .signal import run_deterministic_checks
from .utils import ensure_directory
from .policy import apply_policy



def _filter_summary_for_diff(summary, root: Path, settings: AppSettings):  # type: ignore[no-untyped-def]
    changed_paths = _git_diff_paths(root, settings.changed_from, settings.changed_to)
    filtered_files = [
        source_file for source_file in summary.files if source_file.relative_path in changed_paths
    ]
    return summary.model_copy(
        update={
            "file_count": len(filtered_files),
            "files": filtered_files,
            "language_counts": {
                language: sum(1 for file in filtered_files if file.language == language)
                for language in summary.language_counts
                if any(file.language == language for file in filtered_files)
            },
            "surface_counts": {
                surface: sum(surface in file.surfaces for file in filtered_files)
                for surface in summary.surface_counts
                if any(surface in file.surfaces for file in filtered_files)
            },
        }
    )


def _git_diff_paths(root: Path, changed_from: str | None, changed_to: str | None) -> set[str]:
    command = ["git", "diff", "--name-only"]
    refs = [ref for ref in (changed_from, changed_to) if ref]
    command.extend(refs)
    try:
        output = subprocess.check_output(command, cwd=root, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ConfigurationError(
            "Diff scope requires a readable git repository and valid refs."
        ) from exc
    return {line.strip() for line in output.splitlines() if line.strip()}

def run_agent_review(summary, signals, external_findings, settings, provider):
    raise NotImplementedError

def create_provider(settings):
    raise NotImplementedError


def run_scan(settings: AppSettings) -> ScanResult:
    root = settings.scan_path.resolve()
    if not root.exists():
        raise ScanRuntimeError(f"Scan path does not exist: {root}")

    summary = build_repository_summary(root, settings)
    if settings.scope == ScanScope.DIFF:
        summary = _filter_summary_for_diff(summary, root, settings)

    signals = run_deterministic_checks(summary, settings)
    external_findings = collect_external_findings(root, settings)
    provider = None if settings.provider == settings.provider.NONE else create_provider(settings)
    candidates, findings = run_agent_review(summary, signals, external_findings, settings, provider)
    findings = apply_policy(
        findings,
        fail_on=settings.fail_on,
        min_confidence=settings.min_confidence,
    )
    exit_code = 1 if any(finding.blocking for finding in findings) else 0

    result = ScanResult(
        root=root,
        provider=settings.provider,
        model=settings.model,
        scope=settings.scope,
        findings=findings,
        signals=signals,
        candidates=candidates,
        exit_code=exit_code,
        metadata={
            "file_count": summary.file_count,
            "language_counts": summary.language_counts,
            "surface_counts": summary.surface_counts,
        },
    )

    ensure_directory(settings.artifacts_dir)
    if settings.json_output:
        write_json_report(settings.json_output, result)
    if settings.sarif_output:
        write_sarif_report(settings.sarif_output, result)
    markdown_path = settings.markdown_output
    if markdown_path is None and result.blocking_findings:
        markdown_path = settings.artifacts_dir / "blocking-findings.md"
    if markdown_path:
        write_markdown_report(markdown_path, result)

    return result
