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


from . import __version__

app = typer.Typer(help="CI-first agentic vulnerability scanner.")

console = Console()


def _build_settings(
    scan_path: Path,
    *,
    model: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
    config_path: Path | None = None,
) -> AppSettings:
    overrides = {
        "model": model,
        "base_url": base_url,
        "api_key_env": api_key_env,
    }
    return load_settings(scan_path, config_path=config_path, cli_overrides=overrides)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    model: str | None = typer.Option(None, help="Model identifier for the provider."),
    base_url: str | None = typer.Option(None, help="Base URL or endpoint for provider APIs."),
    api_key_env: str | None = typer.Option(
        None, help="Environment variable containing the API key."
    ),
    config: Path | None = typer.Option(
        None, exists=True, help="Explicit TOML or JSON config file."
    )
) -> None:
    """Scan a repository for vulnerabilities."""
    try:
        settings = _build_settings(
            path,
            model=model,
            base_url=base_url,
            api_key_env=api_key_env,
            config_path=config
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
