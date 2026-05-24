from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from finalreview.cli import app

RUNNER = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_blocks_on_high_severity_fixture():
    result = RUNNER.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "vulnerable_python"),
            "--provider",
            "none",
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert "Dynamic code execution" in result.stdout


def test_scan_warns_only_when_threshold_is_higher():
    result = RUNNER.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "vulnerable_python"),
            "--provider",
            "none",
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 0
    assert "Findings" in result.stdout


def test_scan_provider_failure_returns_runtime_error():
    result = RUNNER.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "clean_repo"),
            "--provider",
            "openai",
            "--model",
            "gpt-test",
        ],
    )

    assert result.exit_code == 2
    assert "Runtime error" in result.stdout
