from __future__ import annotations

import os
import platform
from pathlib import Path

import typer
from rich.console import Console
from .config import AppSettings, load_settings, resolve_api_key_env
from .reporting import print_console_report
from .runner import run_scan
from .exceptions import ConfigurationError, FinalReviewError
from .models import Confidence, OfflineEnricherMode, ProviderKind, ScanScope, Severity



from . import __version__

app = typer.Typer(help="CI-first agentic vulnerability scanner.")

console = Console()


def _build_settings(
    scan_path: Path,
    *,
    provider: ProviderKind | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
    config_path: Path | None = None,
    fail_on: Severity | None = None,
    min_confidence: Confidence | None = None,
    scope: ScanScope | None = None,
    changed_from: str | None = None,
    changed_to: str | None = None,
    json_output: Path | None = None,
    sarif_output: Path | None = None,
    markdown_output: Path | None = None,
    artifacts_dir: Path | None = None,
    max_llm_calls: int | None = None,
    concurrency: int | None = None,
    timeout_seconds: int | None = None,
    offline_enricher: OfflineEnricherMode | None = None,
) -> AppSettings:
    overrides = {
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "api_key_env": api_key_env,
        "fail_on": fail_on,
        "min_confidence": min_confidence,
        "scope": scope,
        "changed_from": changed_from,
        "changed_to": changed_to,
        "json_output": json_output,
        "sarif_output": sarif_output,
        "markdown_output": markdown_output,
        "artifacts_dir": artifacts_dir,
        "max_llm_calls": max_llm_calls,
        "concurrency": concurrency,
        "timeout_seconds": timeout_seconds,
        "offline_enricher": offline_enricher,
    }
    return load_settings(scan_path, config_path=config_path, cli_overrides=overrides)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    provider: ProviderKind | None = typer.Option(None, help="LLM provider to use."),
    model: str | None = typer.Option(None, help="Model identifier for the provider."),
    base_url: str | None = typer.Option(None, help="Base URL or endpoint for provider APIs."),
    api_key_env: str | None = typer.Option(
        None, help="Environment variable containing the API key."
    ),
    config: Path | None = typer.Option(
        None, exists=True, help="Explicit TOML or JSON config file."
    ),
    fail_on: Severity | None = typer.Option(
        None, help="Minimum severity that blocks the pipeline."
    ),
    min_confidence: Confidence | None = typer.Option(
        None, help="Minimum confidence for blocking findings."
    ),
    scope: ScanScope | None = typer.Option(None, help="Scan the full repo or only a diff."),
    changed_from: str | None = typer.Option(None, help="Git ref for diff base."),
    changed_to: str | None = typer.Option(None, help="Git ref for diff head."),
    json_output: Path | None = typer.Option(None, help="Write JSON report to this path."),
    sarif_output: Path | None = typer.Option(None, help="Write SARIF report to this path."),
    markdown_output: Path | None = typer.Option(None, help="Write Markdown report to this path."),
    artifacts_dir: Path | None = typer.Option(None, help="Directory for generated artifacts."),
    max_llm_calls: int | None = typer.Option(None, min=0, help="Maximum LLM calls per scan."),
    concurrency: int | None = typer.Option(
        None, min=1, help="Reserved for future parallel provider calls."
    ),
    timeout_seconds: int | None = typer.Option(None, min=1, help="Provider timeout in seconds."),
    offline_enricher: OfflineEnricherMode | None = typer.Option(
        None, help="External tool enrichment mode."
    ),
) -> None:
    """Scan a repository for vulnerabilities."""
    try:
        settings = _build_settings(
            path,
            provider=provider,
            model=model,
            base_url=base_url,
            api_key_env=api_key_env,
            config_path=config,
            fail_on=fail_on,
            min_confidence=min_confidence,
            scope=scope,
            changed_from=changed_from,
            changed_to=changed_to,
            json_output=json_output,
            sarif_output=sarif_output,
            markdown_output=markdown_output,
            artifacts_dir=artifacts_dir,
            max_llm_calls=max_llm_calls,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
            offline_enricher=offline_enricher,
        )
        result = run_scan(settings)
        print_console_report(result, console)
        raise typer.Exit(code=result.exit_code)
    except ConfigurationError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except FinalReviewError as exc:
        console.print(f"[red]Runtime error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show package version and exit."),
) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit()
