from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import ConfigurationError
from .models import Confidence, OfflineEnricherMode, ProviderKind, ScanScope, Severity

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib


class AppSettings(BaseModel):
    provider: ProviderKind = ProviderKind.NONE
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    fail_on: Severity = Severity.HIGH
    min_confidence: Confidence = Confidence.MEDIUM
    scope: ScanScope = ScanScope.FULL
    changed_from: str | None = None
    changed_to: str | None = None
    json_output: Path | None = None
    sarif_output: Path | None = None
    markdown_output: Path | None = None
    artifacts_dir: Path = Path("finalreview-artifacts")
    cache_dir: Path | None = Path(".finalreview-cache")
    max_llm_calls: int = 12
    concurrency: int = 4
    timeout_seconds: int = 120
    offline_enricher: OfflineEnricherMode = OfflineEnricherMode.AUTO
    whole_file_upload: bool = True
    max_candidate_bytes: int = 12000
    max_evidence_chars: int = 4000
    scan_path: Path = Path(".")


class EnvironmentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FINALREVIEW_",
        case_sensitive=False,
        extra="ignore",
    )

    provider: ProviderKind | None = None
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    fail_on: Severity | None = None
    min_confidence: Confidence | None = None
    scope: ScanScope | None = None
    changed_from: str | None = None
    changed_to: str | None = None
    json_output: Path | None = None
    sarif_output: Path | None = None
    markdown_output: Path | None = None
    artifacts_dir: Path | None = None
    cache_dir: Path | None = None
    max_llm_calls: int | None = None
    concurrency: int | None = None
    timeout_seconds: int | None = None
    offline_enricher: OfflineEnricherMode | None = None
    whole_file_upload: bool | None = None
    max_candidate_bytes: int | None = None
    max_evidence_chars: int | None = None


def _normalize_config_payload(payload: dict[str, Any]) -> dict[str, Any]:
    def normalize_keys(values: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in values.items():
            normalized[key.replace("-", "_")] = value
        return normalized

    if "tool" in payload and isinstance(payload["tool"], dict):
        tool = payload["tool"]
        if "finalreview" in tool and isinstance(tool["finalreview"], dict):
            return normalize_keys(dict(tool["finalreview"]))
    if "finalreview" in payload and isinstance(payload["finalreview"], dict):
        return normalize_keys(dict(payload["finalreview"]))
    return normalize_keys(dict(payload))


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return _normalize_config_payload(tomllib.loads(path.read_text(encoding="utf-8")))


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return _normalize_config_payload(json.loads(path.read_text(encoding="utf-8")))


def _load_config_file(path: Path | None) -> tuple[dict[str, Any], Path | None]:
    if path is None:
        return {}, None
    if not path.exists():
        raise ConfigurationError(f"Config file not found: {path}")
    if path.suffix == ".json":
        return _load_json(path), path.parent
    if path.suffix in {".toml", ".tml"} or path.name == "pyproject.toml":
        return _load_toml(path), path.parent
    raise ConfigurationError(f"Unsupported config format: {path}")


def _load_pyproject(scan_path: Path) -> tuple[dict[str, Any], Path | None]:
    pyproject = scan_path / "pyproject.toml"
    if not pyproject.exists():
        return {}, None
    return _load_toml(pyproject), scan_path


def _resolve_payload_paths(payload: dict[str, Any], base_dir: Path | None) -> dict[str, Any]:
    if base_dir is None:
        return payload
    resolved = dict(payload)
    for name in ("json_output", "sarif_output", "markdown_output", "artifacts_dir", "cache_dir"):
        value = resolved.get(name)
        if isinstance(value, str):
            path = Path(value)
            resolved[name] = str((base_dir / path).resolve()) if not path.is_absolute() else value
        elif isinstance(value, Path) and not value.is_absolute():
            resolved[name] = (base_dir / value).resolve()
    return resolved


def _filter_none(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


def load_settings(
    scan_path: Path,
    *,
    config_path: Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> AppSettings:
    pyproject_payload, pyproject_dir = _load_pyproject(scan_path)
    config_payload, config_dir = _load_config_file(config_path)
    pyproject_payload = _resolve_payload_paths(pyproject_payload, pyproject_dir)
    config_payload = _resolve_payload_paths(config_payload, config_dir)
    env_payload = _filter_none(EnvironmentSettings().model_dump())
    cli_payload = _filter_none(cli_overrides or {})

    merged: dict[str, Any] = {}
    merged.update(pyproject_payload)
    merged.update(config_payload)
    merged.update(env_payload)
    merged.update(cli_payload)
    merged["scan_path"] = scan_path.resolve()

    try:
        settings = AppSettings.model_validate(merged)
    except ValidationError as exc:
        raise ConfigurationError(str(exc)) from exc

    if settings.scope == ScanScope.DIFF and not settings.changed_from and not settings.changed_to:
        raise ConfigurationError("Diff scope requires --changed-from, --changed-to, or both.")
    return settings


def resolve_api_key_env(provider: ProviderKind, explicit_name: str | None) -> str | None:
    if explicit_name:
        return explicit_name
    return {
        ProviderKind.NONE: None,
        ProviderKind.OPENAI: "OPENAI_API_KEY",
        ProviderKind.OPENAI_COMPATIBLE: "OPENAI_API_KEY",
        ProviderKind.AZURE_OPENAI: "AZURE_OPENAI_API_KEY",
        ProviderKind.ANTHROPIC: "ANTHROPIC_API_KEY",
        ProviderKind.GOOGLE: "GOOGLE_API_KEY",
    }[provider]


def read_api_key(provider: ProviderKind, explicit_name: str | None) -> str | None:
    env_name = resolve_api_key_env(provider, explicit_name)
    if env_name is None:
        return None
    return os.getenv(env_name)
