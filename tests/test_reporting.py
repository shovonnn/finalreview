from __future__ import annotations

import json
from pathlib import Path

from finalreview.models import (
    Confidence,
    FileReference,
    Finding,
    ProviderKind,
    ScanResult,
    ScanScope,
    Severity,
)
from finalreview.reporting import write_json_report, write_markdown_report, write_sarif_report


def _sample_result(tmp_path: Path) -> ScanResult:
    finding = Finding(
        title="Dynamic code execution",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-95",
        summary="eval is used",
        reasoning="User input could reach eval.",
        remediation="Remove eval.",
        references=[FileReference(path="app.py", line_start=10, line_end=10)],
        source="heuristic",
        blocking=True,
    )
    return ScanResult(
        root=tmp_path,
        provider=ProviderKind.NONE,
        model=None,
        scope=ScanScope.FULL,
        findings=[finding],
        signals=[],
        candidates=[],
        exit_code=1,
        metadata={"file_count": 1},
    )


def test_report_serialization(tmp_path):
    result = _sample_result(tmp_path)
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    md_path = tmp_path / "report.md"

    write_json_report(json_path, result)
    write_sarif_report(sarif_path, result)
    write_markdown_report(md_path, result)

    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    sarif_payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    markdown_payload = md_path.read_text(encoding="utf-8")

    assert json_payload["exit_code"] == 1
    assert sarif_payload["runs"][0]["results"][0]["ruleId"]
    assert "Dynamic code execution" in markdown_payload
