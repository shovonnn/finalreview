from __future__ import annotations

from collections import Counter
from pathlib import Path

import pathspec

from .config import AppSettings
from .exceptions import ScanRuntimeError
from .models import RepositorySummary, SourceFile
from .utils import is_binary_path, line_count, read_text

SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".finalreview-cache",
    "finalreview-artifacts",
}

SKIP_SUFFIXES = {
    ".min.js",
    ".min.css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".jar",
    ".exe",
    ".dll",
}

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".sql": "sql",
    ".dockerfile": "dockerfile",
}

SURFACE_PATTERNS: dict[str, tuple[str, ...]] = {
    "auth": ("auth", "login", "jwt", "oauth", "session"),
    "http": ("route", "request", "response", "express", "fastapi", "flask", "gin", "http"),
    "template": ("template", "jinja", "render", "innerhtml", "dangerouslysetinnerhtml"),
    "subprocess": ("subprocess", "popen", "exec", "command", "shell=true"),
    "database": ("select ", "insert ", "update ", "delete ", "query", "cursor", "execute"),
    "secret": ("password", "secret", "token", "apikey", "api_key", "private_key"),
    "iac": ("terraform", "kubernetes", "docker", "privileged", "securitygroup"),
    "ci": ("github/workflows", "gitlab-ci", "jenkins", "azure-pipelines"),
}


def _load_gitignore(root: Path):  # type: ignore[no-untyped-def]
    patterns: list[str] = []
    gitignore = root / ".gitignore"
    if gitignore.exists():
        patterns.extend(gitignore.read_text(encoding="utf-8").splitlines())
    return pathspec.PathSpec.from_lines("gitignore", patterns)


def _is_skipped(path: Path, relative_path: str, spec) -> bool:  # type: ignore[no-untyped-def]
    if any(part in SKIP_DIRECTORIES for part in Path(relative_path).parts):
        return True
    if spec.match_file(relative_path):
        return True
    lower_name = path.name.lower()
    if lower_name == "dockerfile":
        return False
    return any(lower_name.endswith(suffix) for suffix in SKIP_SUFFIXES)


def _detect_language(path: Path) -> str:
    lower_name = path.name.lower()
    if lower_name == "dockerfile":
        return "dockerfile"
    return LANGUAGE_MAP.get(path.suffix.lower(), "text")


def _detect_surfaces(relative_path: str, text: str) -> list[str]:
    lowered = f"{relative_path.lower()}\n{text[:12000].lower()}"
    surfaces = [
        surface
        for surface, patterns in SURFACE_PATTERNS.items()
        if any(pattern in lowered for pattern in patterns)
    ]
    return sorted(set(surfaces))


def iter_scan_files(root: Path, settings: AppSettings) -> list[SourceFile]:
    spec = _load_gitignore(root)
    files: list[SourceFile] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_path = path.relative_to(root).as_posix()
        if _is_skipped(path, relative_path, spec):
            continue
        if is_binary_path(path):
            continue
        try:
            text = read_text(path)
        except OSError as exc:  # pragma: no cover - filesystem edge case
            raise ScanRuntimeError(f"Failed to read {path}: {exc}") from exc
        files.append(
            SourceFile(
                path=path.resolve(),
                relative_path=relative_path,
                language=_detect_language(path),
                surfaces=_detect_surfaces(relative_path, text),
                size=path.stat().st_size,
                line_count=line_count(text),
            )
        )
    return files


def build_repository_summary(root: Path, settings: AppSettings) -> RepositorySummary:
    files = iter_scan_files(root, settings)
    language_counts = Counter(file.language for file in files)
    surface_counts = Counter(surface for file in files for surface in file.surfaces)
    return RepositorySummary(
        root=root.resolve(),
        file_count=len(files),
        language_counts=dict(sorted(language_counts.items())),
        surface_counts=dict(sorted(surface_counts.items())),
        files=files,
    )
