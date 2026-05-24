from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    NEVER = "never"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.NEVER: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {
            Confidence.LOW: 1,
            Confidence.MEDIUM: 2,
            Confidence.HIGH: 3,
        }[self]


class ProviderKind(str, Enum):
    NONE = "none"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE_OPENAI = "azure-openai"
    OPENAI_COMPATIBLE = "openai-compatible"


class ScanScope(str, Enum):
    FULL = "full"
    DIFF = "diff"


class OfflineEnricherMode(str, Enum):
    AUTO = "auto"
    ON = "on"
    OFF = "off"


class FileReference(BaseModel):
    path: str
    line_start: int | None = None
    line_end: int | None = None


class Evidence(BaseModel):
    path: str
    excerpt: str
    line_start: int | None = None
    line_end: int | None = None


class Signal(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str | None = None
    summary: str
    reasoning: str
    remediation: str
    path: str
    line_start: int | None = None
    line_end: int | None = None
    tags: list[str] = Field(default_factory=list)
    source: str = "heuristic"

    @property
    def priority(self) -> int:
        return (self.severity.rank * 10) + self.confidence.rank


class Finding(BaseModel):
    id: str | None = None
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str | None = None
    summary: str
    reasoning: str
    remediation: str
    references: list[FileReference] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    source: str = "agent-review"
    provider: str | None = None
    model: str | None = None
    blocking: bool = False
    fingerprint: str | None = None

    @model_validator(mode="after")
    def _assign_identity(self) -> Finding:
        if self.fingerprint is None:
            first_reference = self.references[0] if self.references else None
            key = self.cwe or self.rule_id or self.title
            if first_reference:
                ref_token = (
                    f"{first_reference.path}:{first_reference.line_start}:{first_reference.line_end}"
                )
                self.fingerprint = f"{key}:{ref_token}".lower()
            else:
                self.fingerprint = f"{key}:{self.title}".lower()
        if self.id is None:
            self.id = self.fingerprint.replace(" ", "-")
        return self


class SourceFile(BaseModel):
    path: Path
    relative_path: str
    language: str
    surfaces: list[str] = Field(default_factory=list)
    size: int
    line_count: int


class CandidatePack(BaseModel):
    id: str
    path: str
    language: str
    surfaces: list[str] = Field(default_factory=list)
    rationale: str
    priority: int
    context: str
    signals: list[Signal] = Field(default_factory=list)


class RepositorySummary(BaseModel):
    root: Path
    file_count: int
    language_counts: dict[str, int] = Field(default_factory=dict)
    surface_counts: dict[str, int] = Field(default_factory=dict)
    files: list[SourceFile] = Field(default_factory=list)


class ScanResult(BaseModel):
    root: Path
    provider: ProviderKind
    model: str | None
    scope: ScanScope
    findings: list[Finding]
    signals: list[Signal]
    candidates: list[CandidatePack]
    exit_code: int
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def blocking_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.blocking]

    @property
    def warning_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if not finding.blocking]
