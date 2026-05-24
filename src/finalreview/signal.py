from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import cast

from .config import AppSettings
from .models import Confidence, RepositorySummary, Severity, Signal
from .utils import read_text

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key|private[_-]?key)\b.{0,20}[:=].{0,5}[\"'][^\"']{8,}[\"']"
)


def _make_signal(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    cwe: str | None,
    summary: str,
    reasoning: str,
    remediation: str,
    path: str,
    line_start: int | None,
    line_end: int | None,
    tags: list[str],
) -> Signal:
    return Signal(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        cwe=cwe,
        summary=summary,
        reasoning=reasoning,
        remediation=remediation,
        path=path,
        line_start=line_start,
        line_end=line_end,
        tags=tags,
    )


class PythonSignalVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.signals: list[Signal] = []

    def _append(self, signal: Signal) -> None:
        self.signals.append(signal)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""

        if func_name in {"eval", "exec"}:
            self._append(
                _make_signal(
                    rule_id="py-eval-exec",
                    title="Dynamic code execution",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-95",
                    summary="The code dynamically evaluates Python code.",
                    reasoning="Dynamic execution can lead to remote code execution when input reaches the call.",
                    remediation="Replace dynamic evaluation with explicit parsing or a safe allowlist.",
                    path=self.path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    tags=["python", "rce"],
                )
            )

        if func_name.startswith("subprocess.") and any(
            keyword.arg == "shell" and getattr(keyword.value, "value", None) is True
            for keyword in node.keywords
        ):
            self._append(
                _make_signal(
                    rule_id="py-subprocess-shell",
                    title="Shell execution with shell=True",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-78",
                    summary="A subprocess call enables shell parsing.",
                    reasoning="Untrusted input can escape command boundaries when the shell is enabled.",
                    remediation="Pass argv arrays directly and keep shell=False.",
                    path=self.path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    tags=["python", "command-injection"],
                )
            )

        if func_name in {"pickle.load", "pickle.loads"}:
            self._append(
                _make_signal(
                    rule_id="py-pickle-load",
                    title="Unsafe pickle deserialization",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-502",
                    summary="Pickle data is deserialized in Python.",
                    reasoning="Pickle payloads can execute attacker-controlled code.",
                    remediation="Use safe formats such as JSON or ensure the input is fully trusted.",
                    path=self.path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    tags=["python", "deserialization"],
                )
            )

        if func_name == "yaml.load":
            self._append(
                _make_signal(
                    rule_id="py-yaml-load",
                    title="Potentially unsafe YAML load",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe="CWE-20",
                    summary="yaml.load is used without an obviously safe loader.",
                    reasoning="Unsafe YAML loaders can construct arbitrary Python objects.",
                    remediation="Use yaml.safe_load or pass a safe Loader explicitly.",
                    path=self.path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    tags=["python", "deserialization"],
                )
            )

        if func_name.startswith("requests.") and any(
            keyword.arg == "verify" and getattr(keyword.value, "value", None) is False
            for keyword in node.keywords
        ):
            self._append(
                _make_signal(
                    rule_id="py-requests-no-verify",
                    title="TLS verification disabled",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    cwe="CWE-295",
                    summary="An HTTP request disables certificate verification.",
                    reasoning="Disabling TLS verification enables man-in-the-middle interception.",
                    remediation="Keep certificate verification enabled or pin trusted certificates.",
                    path=self.path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    tags=["python", "tls"],
                )
            )

        self.generic_visit(node)


REGEX_RULES: dict[str, list[tuple[re.Pattern[str], dict[str, object]]]] = {
    "javascript": [
        (
            re.compile(r"\beval\s*\("),
            {
                "rule_id": "js-eval",
                "title": "Dynamic JavaScript evaluation",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-95",
                "summary": "JavaScript eval is used.",
                "reasoning": "eval can execute attacker-controlled script when fed user input.",
                "remediation": "Remove eval and replace it with explicit parsing or safe mappings.",
                "tags": ["javascript", "rce"],
            },
        ),
        (
            re.compile(r"child_process\.(exec|execSync)\s*\("),
            {
                "rule_id": "js-child-process-exec",
                "title": "Shell command execution",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-78",
                "summary": "Node child_process executes shell commands.",
                "reasoning": "String commands can become command injection sinks.",
                "remediation": "Use execFile or spawn with fixed argument vectors.",
                "tags": ["javascript", "command-injection"],
            },
        ),
        (
            re.compile(r"\.innerHTML\s*="),
            {
                "rule_id": "js-innerhtml",
                "title": "Raw HTML injection sink",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe": "CWE-79",
                "summary": "Raw HTML is written directly into the DOM.",
                "reasoning": "Unsanitized input may become a client-side XSS vulnerability.",
                "remediation": "Prefer text nodes or sanitize HTML before injection.",
                "tags": ["javascript", "xss"],
            },
        ),
    ],
    "typescript": [],
    "go": [
        (
            re.compile(r"exec\.Command\s*\(\s*\"(?:/bin/sh|sh)\"\s*,\s*\"-c\""),
            {
                "rule_id": "go-shell-command",
                "title": "Shell execution in Go",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-78",
                "summary": "Go code invokes a shell command through exec.Command.",
                "reasoning": "Shell invocation creates a direct command injection boundary.",
                "remediation": "Pass fixed executables and argument arrays instead of a shell.",
                "tags": ["go", "command-injection"],
            },
        ),
        (
            re.compile(r"InsecureSkipVerify\s*:\s*true"),
            {
                "rule_id": "go-insecure-skip-verify",
                "title": "TLS verification disabled in Go",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-295",
                "summary": "TLS verification is disabled in Go configuration.",
                "reasoning": "This weakens transport integrity and enables interception.",
                "remediation": "Keep TLS verification enabled or pin trusted certificates.",
                "tags": ["go", "tls"],
            },
        ),
    ],
    "java": [
        (
            re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
            {
                "rule_id": "java-runtime-exec",
                "title": "Runtime command execution",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-78",
                "summary": "Java Runtime.exec is used.",
                "reasoning": "This is a frequent command injection sink.",
                "remediation": "Use fixed command arrays and validate inputs rigorously.",
                "tags": ["java", "command-injection"],
            },
        ),
        (
            re.compile(r"ObjectInputStream"),
            {
                "rule_id": "java-object-input-stream",
                "title": "Potential unsafe Java deserialization",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe": "CWE-502",
                "summary": "Java object deserialization API is used.",
                "reasoning": "Untrusted serialized objects can trigger gadget chains.",
                "remediation": "Avoid native Java serialization for untrusted data.",
                "tags": ["java", "deserialization"],
            },
        ),
    ],
    "shell": [
        (
            re.compile(r"curl\b[^\n|]*\|\s*(?:sh|bash)"),
            {
                "rule_id": "sh-curl-pipe-shell",
                "title": "Remote script piped to shell",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-494",
                "summary": "A shell script is executed directly from a remote response.",
                "reasoning": "This bypasses integrity checks and increases supply-chain risk.",
                "remediation": "Download, verify, and review scripts before execution.",
                "tags": ["shell", "supply-chain"],
            },
        ),
        (
            re.compile(r"\beval\s+[\"'$]"),
            {
                "rule_id": "sh-eval",
                "title": "Shell eval usage",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe": "CWE-95",
                "summary": "Shell eval is used.",
                "reasoning": "eval can execute attacker-controlled content in shell contexts.",
                "remediation": "Avoid eval and build commands as explicit arguments.",
                "tags": ["shell", "command-injection"],
            },
        ),
    ],
    "yaml": [
        (
            re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
            {
                "rule_id": "yaml-privileged-container",
                "title": "Privileged container configuration",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-250",
                "summary": "A YAML manifest grants privileged container access.",
                "reasoning": "Privileged containers can escape normal workload boundaries.",
                "remediation": "Drop privileged mode and grant only narrow capabilities.",
                "tags": ["yaml", "kubernetes"],
            },
        ),
        (
            re.compile(r"pull_request_target", re.IGNORECASE),
            {
                "rule_id": "yaml-pull-request-target",
                "title": "Potentially dangerous pull_request_target workflow",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe": "CWE-829",
                "summary": "A workflow triggers on pull_request_target.",
                "reasoning": "This event can expose secrets to attacker-controlled pull requests if used unsafely.",
                "remediation": "Restrict untrusted code execution and review secret exposure in the workflow.",
                "tags": ["yaml", "ci"],
            },
        ),
    ],
    "dockerfile": [
        (
            re.compile(r"^\s*USER\s+root\b", re.MULTILINE | re.IGNORECASE),
            {
                "rule_id": "dockerfile-user-root",
                "title": "Container runs as root",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-250",
                "summary": "The Dockerfile sets the runtime user to root.",
                "reasoning": "Root containers increase impact if the workload is compromised.",
                "remediation": "Use a dedicated non-root runtime user.",
                "tags": ["docker", "container"],
            },
        ),
        (
            re.compile(r"curl\b[^\n|]*\|\s*(?:sh|bash)", re.IGNORECASE),
            {
                "rule_id": "dockerfile-curl-pipe-shell",
                "title": "Remote script executed during image build",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-494",
                "summary": "The Dockerfile pipes a remote script into a shell.",
                "reasoning": "This creates a supply-chain execution risk during builds.",
                "remediation": "Download and verify artifacts before executing them.",
                "tags": ["docker", "supply-chain"],
            },
        ),
    ],
    "terraform": [
        (
            re.compile(r"0\.0\.0\.0/0"),
            {
                "rule_id": "tf-open-cidr",
                "title": "Terraform resource exposes a global CIDR",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe": "CWE-284",
                "summary": "A Terraform file contains an unrestricted network CIDR.",
                "reasoning": "Global exposure is frequently broader than intended for security-sensitive resources.",
                "remediation": "Restrict ingress or egress to the minimum required ranges.",
                "tags": ["terraform", "network"],
            },
        ),
    ],
}
REGEX_RULES["typescript"] = REGEX_RULES["javascript"]


def _scan_python(path: Path, relative_path: str, text: str) -> list[Signal]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    visitor = PythonSignalVisitor(relative_path)
    visitor.visit(tree)
    return visitor.signals


def _scan_regex_language(language: str, relative_path: str, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for pattern, metadata in REGEX_RULES.get(language, []):
        for match in pattern.finditer(text):
            line_start = text.count("\n", 0, match.start()) + 1
            signals.append(
                _make_signal(
                    rule_id=str(metadata["rule_id"]),
                    title=str(metadata["title"]),
                    severity=metadata["severity"],  # type: ignore[arg-type]
                    confidence=metadata["confidence"],  # type: ignore[arg-type]
                    cwe=metadata["cwe"],  # type: ignore[arg-type]
                    summary=str(metadata["summary"]),
                    reasoning=str(metadata["reasoning"]),
                    remediation=str(metadata["remediation"]),
                    path=relative_path,
                    line_start=line_start,
                    line_end=line_start,
                    tags=list(cast(list[str], metadata["tags"])),
                )
            )
    return signals


def _scan_secrets(relative_path: str, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for match in SECRET_ASSIGNMENT_RE.finditer(text):
        line_start = text.count("\n", 0, match.start()) + 1
        signals.append(
            _make_signal(
                rule_id="generic-hardcoded-secret",
                title="Potential hardcoded secret",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-798",
                summary="A likely secret is embedded directly in source code.",
                reasoning="Hardcoded secrets are commonly leaked through source control and build logs.",
                remediation="Move secrets to a managed secret store or environment variable.",
                path=relative_path,
                line_start=line_start,
                line_end=line_start,
                tags=["secret"],
            )
        )
    return signals


def run_deterministic_checks(summary: RepositorySummary, settings: AppSettings) -> list[Signal]:
    findings: list[Signal] = []
    for source_file in summary.files:
        text = read_text(source_file.path)
        if source_file.language == "python":
            findings.extend(_scan_python(source_file.path, source_file.relative_path, text))
        findings.extend(_scan_regex_language(source_file.language, source_file.relative_path, text))
        findings.extend(_scan_secrets(source_file.relative_path, text))
    return sorted(findings, key=lambda item: (-item.priority, item.path, item.line_start or 0))
