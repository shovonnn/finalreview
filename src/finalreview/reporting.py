from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from .models import Finding, ScanResult, Severity
from .utils import ensure_directory


def print_console_report(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    summary_table = Table(title="finalreview summary")
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    summary_table.add_row("Root", str(result.root))
    summary_table.add_row("Provider", result.provider.value)
    summary_table.add_row("Model", result.model or "-")
    summary_table.add_row("Files", str(result.metadata.get("file_count", 0)))
    summary_table.add_row("Signals", str(len(result.signals)))
    summary_table.add_row("Candidates", str(len(result.candidates)))
    summary_table.add_row("Findings", str(len(result.findings)))
    summary_table.add_row("Blocking", str(len(result.blocking_findings)))
    console.print(summary_table)

    if not result.findings:
        console.print("[green]No vulnerabilities found.[/green]")
        return

    finding_table = Table(title="Findings")
    finding_table.add_column("Severity")
    finding_table.add_column("Confidence")
    finding_table.add_column("Source")
    finding_table.add_column("Location")
    finding_table.add_column("Title")
    for finding in result.findings:
        location = finding.references[0].path if finding.references else "-"
        if finding.references and finding.references[0].line_start:
            location = f"{location}:{finding.references[0].line_start}"
        color = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.NEVER: "white",
        }[finding.severity]
        finding_table.add_row(
            f"[{color}]{finding.severity.value}[/{color}]",
            finding.confidence.value,
            finding.source,
            location,
            finding.title,
        )
    console.print(finding_table)


def _finding_payload(findings: list[Finding]) -> list[dict[str, Any]]:
    return [finding.model_dump(mode="json") for finding in findings]


def write_json_report(path: Path, result: ScanResult) -> None:
    ensure_directory(path.parent)
    payload = {
        "root": str(result.root),
        "provider": result.provider.value,
        "model": result.model,
        "scope": result.scope.value,
        "exit_code": result.exit_code,
        "metadata": result.metadata,
        "findings": _finding_payload(result.findings),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_markdown_report(path: Path, result: ScanResult) -> None:
    ensure_directory(path.parent)
    lines = [
        "# finalreview report",
        "",
        f"- Root: `{result.root}`",
        f"- Provider: `{result.provider.value}`",
        f"- Model: `{result.model or '-'}`",
        f"- Files scanned: `{result.metadata.get('file_count', 0)}`",
        f"- Findings: `{len(result.findings)}`",
        f"- Blocking findings: `{len(result.blocking_findings)}`",
        "",
    ]
    if not result.findings:
        lines.append("No vulnerabilities found.")
    for finding in result.findings:
        location = "-"
        if finding.references:
            ref = finding.references[0]
            location = ref.path
            if ref.line_start:
                location = f"{location}:{ref.line_start}"
        lines.extend(
            [
                f"## {finding.title}",
                "",
                f"- Severity: `{finding.severity.value}`",
                f"- Confidence: `{finding.confidence.value}`",
                f"- Blocking: `{str(finding.blocking).lower()}`",
                f"- CWE: `{finding.cwe or '-'}`",
                f"- Location: `{location}`",
                f"- Source: `{finding.source}`",
                "",
                finding.summary,
                "",
                "### Reasoning",
                "",
                finding.reasoning,
                "",
                "### Remediation",
                "",
                finding.remediation,
                "",
            ]
        )
        if finding.evidence:
            lines.extend(["### Evidence", ""])
            for evidence in finding.evidence:
                lines.extend(
                    [
                        f"- `{evidence.path}:{evidence.line_start or '-'}-{evidence.line_end or '-'}`",
                        "",
                        "```text",
                        evidence.excerpt,
                        "```",
                        "",
                    ]
                )
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _sarif_level(finding: Finding) -> str:
    if finding.severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error" if finding.blocking else "warning"
    if finding.severity == Severity.MEDIUM:
        return "warning"
    return "note"


def write_sarif_report(path: Path, result: ScanResult) -> None:
    ensure_directory(path.parent)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in result.findings:
        rule_id = finding.rule_id or finding.cwe or finding.id or finding.title
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.summary},
                "help": {"text": finding.remediation},
                "properties": {
                    "tags": finding.tags,
                    "precision": finding.confidence.value,
                    "problem.severity": finding.severity.value,
                },
            }
        locations = []
        for reference in finding.references:
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": reference.path},
                        "region": {"startLine": reference.line_start or 1},
                    }
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding),
                "message": {"text": finding.summary},
                "locations": locations
                or [{"physicalLocation": {"artifactLocation": {"uri": "unknown"}}}],
                "properties": {
                    "confidence": finding.confidence.value,
                    "severity": finding.severity.value,
                    "blocking": finding.blocking,
                },
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "finalreview",
                        "informationUri": "https://github.com/your-org/finalreview",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
