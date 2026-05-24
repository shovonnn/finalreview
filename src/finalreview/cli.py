from __future__ import annotations

import os
import platform
from pathlib import Path

import typer
from rich.console import Console

from . import __version__

app = typer.Typer(help="CI-first agentic vulnerability scanner.")

console = Console()


@app.command()
def scan(
) -> None:
    """Scan a repository for vulnerabilities."""
    console.print("Scanning repository... (not implemented yet)")


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show package version and exit."),
) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit()
