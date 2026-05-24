from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .config import AppSettings
from .models import Confidence, FileReference, Finding, OfflineEnricherMode, Severity

KNOWN_REPORT_NAMES = {
    "semgrep": "semgrep.json",
    "bandit": "bandit.json",
    "gitleaks": "gitleaks.json",
    "trivy": "trivy.json",
}


def _finding_from_external(tool_name: str, payload: dict[str, Any]) -> Finding:
    severity_raw = str(payload.get("severity", "medium")).lower()
    severity = (
        Severity(severity_raw) if severity_raw in Severity._value2member_map_ else Severity.MEDIUM
    )
    path = payload.get("path") or payload.get("filename") or payload.get("target") or "<unknown>"
    line = payload.get("line") or payload.get("start_line")
    title = payload.get("title") or payload.get("rule_id") or payload.get("check_id") or tool_name
    summary = payload.get("message") or payload.get("description") or "External tool finding."
    return Finding(
        title=str(title),
        severity=severity,
        confidence=Confidence.MEDIUM,
        cwe=payload.get("cwe"),
        summary=str(summary),
        reasoning=f"Imported from {tool_name} external scan output.",
        remediation=str(
            payload.get("remediation") or "Review the external tool output and patch accordingly."
        ),
        references=[
            FileReference(
                path=str(path),
                line_start=int(line) if line else None,
                line_end=int(line) if line else None,
            )
        ],
        evidence=[],
        source=f"external:{tool_name}",
        rule_id=str(payload.get("rule_id") or payload.get("check_id") or tool_name),
        tags=[tool_name],
    )


def _flatten_external_payload(tool_name: str, payload: Any) -> list[Finding]:
    if isinstance(payload, list):
        return [
            _finding_from_external(tool_name, item) for item in payload if isinstance(item, dict)
        ]
    if not isinstance(payload, dict):
        return []
    for key in ("results", "findings", "runs", "issues"):
        value = payload.get(key)
        if isinstance(value, list):
            if key == "runs":
                findings: list[Finding] = []
                for run in value:
                    if not isinstance(run, dict):
                        continue
                    for result in run.get("results", []):
                        if not isinstance(result, dict):
                            continue
                        findings.append(
                            _finding_from_external(
                                tool_name,
                                {
                                    "rule_id": result.get("ruleId"),
                                    "message": result.get("message", {}).get("text"),
                                    "severity": result.get("level", "medium"),
                                    "path": (
                                        result.get("locations", [{}])[0]
                                        .get("physicalLocation", {})
                                        .get("artifactLocation", {})
                                        .get("uri")
                                    ),
                                    "line": (
                                        result.get("locations", [{}])[0]
                                        .get("physicalLocation", {})
                                        .get("region", {})
                                        .get("startLine")
                                    ),
                                },
                            )
                        )
                return findings
            return [
                _finding_from_external(tool_name, item) for item in value if isinstance(item, dict)
            ]
    return [_finding_from_external(tool_name, payload)]


def _read_report(path: Path, tool_name: str) -> list[Finding]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return _flatten_external_payload(tool_name, payload)


def _run_tool_if_available(root: Path, tool_name: str, timeout_seconds: int) -> list[Finding]:
    executable = shutil.which(tool_name)
    if executable is None:
        return []
    with tempfile.TemporaryDirectory(prefix=f"finalreview-{tool_name}-") as tmpdir:
        output_path = Path(tmpdir) / f"{tool_name}.json"
        commands = {
            "semgrep": [
                executable,
                "scan",
                "--quiet",
                "--json",
                "--output",
                str(output_path),
                str(root),
            ],
            "bandit": [executable, "-r", str(root), "-f", "json", "-o", str(output_path)],
            "gitleaks": [
                executable,
                "detect",
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                str(output_path),
                str(root),
            ],
            "trivy": [
                executable,
                "fs",
                "--format",
                "json",
                "--output",
                str(output_path),
                str(root),
            ],
        }
        command = commands.get(tool_name)
        if command is None:
            return []
        try:
            subprocess.run(
                command,
                cwd=root,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if output_path.exists():
            return _read_report(output_path, tool_name)
    return []


def collect_external_findings(root: Path, settings: AppSettings) -> list[Finding]:
    if settings.offline_enricher == OfflineEnricherMode.OFF:
        return []

    report_search_roots = [root, settings.artifacts_dir]
    findings: list[Finding] = []
    for tool_name, report_name in KNOWN_REPORT_NAMES.items():
        for search_root in report_search_roots:
            report_path = search_root / report_name
            if report_path.exists():
                findings.extend(_read_report(report_path, tool_name))
                break
        else:
            if settings.offline_enricher == OfflineEnricherMode.ON:
                findings.extend(_run_tool_if_available(root, tool_name, settings.timeout_seconds))
    return findings
